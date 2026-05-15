#!/usr/bin/env bash
# Parche Horus: captura SSH local y conexiones SSH remotas que atraviesan la VPN.
# Ejecutar despues de instalar Horus desde la version con Wazuh/wildcard.
# No modifica certificados, wildcard, mitmproxy ni logs HTTP/Wazuh.

set -euo pipefail

HORUS_DIR="/opt/horus"
SSH_WATCHER="${HORUS_DIR}/ssh_log_watcher.py"
HORUS_PY="${HORUS_DIR}/horus.py"
SERVICE="horus.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Este parche necesita permisos de root. Ejecuta con sudo."
  exit 1
fi

if [ ! -f "${HORUS_PY}" ]; then
  echo "ERROR: no existe ${HORUS_PY}. Instala Horus primero."
  exit 1
fi

VPN_NET_PREFIX="$(python3 - <<'PY'
import re
c=open('/opt/horus/horus.py').read()
m=re.search(r'VPN_NET\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+\.)0/24"', c)
print(m.group(1) if m else '')
PY
)"

if [ -z "${VPN_NET_PREFIX}" ]; then
  read -r -p "No pude detectar el prefijo VPN. Ingresa prefijo /24, ej 192.168.2.: " VPN_NET_PREFIX
fi

cp -a "${SSH_WATCHER}" "${SSH_WATCHER}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
cp -a "${HORUS_PY}" "${HORUS_PY}.bak.$(date +%Y%m%d%H%M%S)"

printf 'VPN_NET_PREFIX = "%s"\n\n' "${VPN_NET_PREFIX}" > "${SSH_WATCHER}"
cat >> "${SSH_WATCHER}" <<'PYSSH'
import datetime
import os
import queue
import re
import subprocess
import threading

OUTFILE = "/var/log/horus/ssh_access.log"
REMOTE_PREFIX = "HORUS_SSH_REMOTE"

os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
LOGFH = open(OUTFILE, "a", buffering=1)

RE_ACC = re.compile(r"Accepted .* for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_FAIL = re.compile(r"Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_SRC = re.compile(r"\bSRC=(?P<src>\d+\.\d+\.\d+\.\d+)")
RE_DST = re.compile(r"\bDST=(?P<dst>\d+\.\d+\.\d+\.\d+)")
RE_SPT = re.compile(r"\bSPT=(?P<spt>\d+)")
RE_DPT = re.compile(r"\bDPT=(?P<dpt>\d+)")
RE_PROTO = re.compile(r"\bPROTO=(?P<proto>\S+)")

event_queue = queue.Queue()
seen_remote = set()


def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def write_event(line):
    LOGFH.write(line + "\n")


def enqueue_stream(cmd, source_name):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as exc:
        write_event(f"{now()}\t-\tERROR\t-\tWATCHER\t{source_name}: {exc}")
        return
    try:
        for raw in proc.stdout:
            event_queue.put((source_name, raw.strip()))
    except Exception as exc:
        write_event(f"{now()}\t-\tERROR\t-\tWATCHER\t{source_name}: {exc}")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


def start_local_ssh_stream():
    try:
        subprocess.run(["journalctl", "-u", "sshd.service", "-n", "1", "--no-pager"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cmd = ["journalctl", "-u", "sshd.service", "-f", "-o", "short"]
    except Exception:
        cmd = ["tail", "-F", "/var/log/auth.log"]
    threading.Thread(target=enqueue_stream, args=(cmd, "local_ssh"), daemon=True).start()


def start_remote_ssh_stream():
    sources = [
        ["journalctl", "-k", "-f", "-o", "short"],
        ["tail", "-F", "/var/log/kern.log"],
        ["tail", "-F", "/var/log/messages"],
    ]
    for cmd in sources:
        try:
            if cmd[0] == "journalctl":
                probe = subprocess.run(["journalctl", "-k", "-n", "1", "--no-pager"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                probe = subprocess.run(["test", "-e", cmd[-1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                threading.Thread(target=enqueue_stream, args=(cmd, "remote_ssh"), daemon=True).start()
                return
        except Exception:
            continue
    write_event(f"{now()}\t-\tERROR\t-\tWATCHER\tNo se pudo abrir fuente de logs kernel para REMOTE_SSH")


def parse_local_ssh(line):
    m = RE_ACC.search(line) or RE_FAIL.search(line)
    if not m:
        return
    ip, user = m.group("ip"), m.group("user")
    if not ip.startswith(VPN_NET_PREFIX):
        return
    ev = "ACCEPTED" if "Accepted " in line else "FAILED"
    write_event(f"{now()}\t{ip}\t{ev}\t{user}\tLOCAL_SSH\t-\t{line}")


def parse_remote_ssh(line):
    if REMOTE_PREFIX not in line:
        return
    src_m = RE_SRC.search(line)
    dst_m = RE_DST.search(line)
    spt_m = RE_SPT.search(line)
    dpt_m = RE_DPT.search(line)
    proto_m = RE_PROTO.search(line)
    if not src_m or not dst_m or not dpt_m:
        return
    src = src_m.group("src")
    dst = dst_m.group("dst")
    spt = spt_m.group("spt") if spt_m else "-"
    dpt = dpt_m.group("dpt")
    proto = proto_m.group("proto") if proto_m else "TCP"
    if dpt != "22" or not src.startswith(VPN_NET_PREFIX):
        return
    dedup_key = f"{src}:{spt}>{dst}:{dpt}"
    if dedup_key in seen_remote:
        return
    seen_remote.add(dedup_key)
    if len(seen_remote) > 10000:
        seen_remote.clear()
    write_event(f"{now()}\t{src}\tCONNECT\t-\tREMOTE_SSH\t{dst}:{dpt}\tSPT={spt}\tPROTO={proto}\t{line}")


def run():
    start_local_ssh_stream()
    start_remote_ssh_stream()
    while True:
        source, line = event_queue.get()
        if source == "local_ssh":
            parse_local_ssh(line)
        elif source == "remote_ssh":
            parse_remote_ssh(line)


if __name__ == "__main__":
    run()
PYSSH

python3 - <<'PY'
from pathlib import Path
p = Path('/opt/horus/horus.py')
s = p.read_text()

if 'def filter_rule_exists(rule):' not in s:
    marker = '''def rule_exists(rule):\n    try:\n        subprocess.check_call(["iptables", "-t", "nat", "-C", "PREROUTING"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n        return True\n    except Exception:\n        return False\n'''
    insert = marker + r'''

def filter_rule_exists(rule):
    try:
        subprocess.check_call(["iptables", "-C", "FORWARD"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def ssh_remote_rule():
    return [
        "-i", IF_IN,
        "-s", VPN_NET,
        "-p", "tcp",
        "--dport", "22",
        "-m", "conntrack",
        "--ctstate", "NEW",
        "-j", "LOG",
        "--log-prefix", "HORUS_SSH_REMOTE ",
        "--log-level", "4",
    ]


def add_ssh_remote_logging():
    rule = ssh_remote_rule()
    try:
        if not filter_rule_exists(rule):
            run_cmd(["iptables", "-I", "FORWARD", "1"] + rule)
    except Exception as e:
        print("Error agregando regla SSH remoto:", e)


def del_ssh_remote_logging():
    rule = ssh_remote_rule()
    try:
        while filter_rule_exists(rule):
            run_cmd(["iptables", "-D", "FORWARD"] + rule)
    except Exception as e:
        print("Error borrando regla SSH remoto:", e)
'''
    s = s.replace(marker, insert)

if 'add_ssh_remote_logging()' not in s.split('def add_iptables():', 1)[1].split('def del_iptables():', 1)[0]:
    s = s.replace('''    try:\n        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])\n    except Exception:\n        pass\n\ndef del_iptables():\n''', '''    add_ssh_remote_logging()\n    try:\n        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])\n    except Exception:\n        pass\n\ndef del_iptables():\n    del_ssh_remote_logging()\n''')

p.write_text(s)
PY

chmod 644 "${SSH_WATCHER}"
chmod 755 "${HORUS_PY}"
systemctl restart "${SERVICE}"

echo "Parche aplicado. Revisa: tail -f /var/log/horus/ssh_access.log"
