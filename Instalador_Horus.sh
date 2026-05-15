#!/usr/bin/env bash
# Instalador_Horus.sh
# Ejecutar como root.
# Herramienta desarrollada por H4cker.
#
# Esta version conserva la base con Wazuh JSON + CA/wildcard del commit:
# c15579a95ff967bf2dcdde39b017a7c35a4a8bbc
# y aplica automaticamente la mejora de captura SSH remota durante la misma instalacion.

set -euo pipefail
IFS=$'\n\t'

BASE_COMMIT="c15579a95ff967bf2dcdde39b017a7c35a4a8bbc"
BASE_INSTALLER_URL="https://raw.githubusercontent.com/Carlos-CodeBot/Horus/${BASE_COMMIT}/Instalador_Horus.sh"
TMP_DIR="$(mktemp -d)"
BASE_INSTALLER="${TMP_DIR}/Instalador_Horus.base.sh"

cleanup() {
  rm -rf "${TMP_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script necesita permisos de root. Ejecuta con sudo."
  exit 1
fi

download_base_installer() {
  echo "==> Descargando instalador base con Wazuh/wildcard (${BASE_COMMIT})..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${BASE_INSTALLER_URL}" -o "${BASE_INSTALLER}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${BASE_INSTALLER}" "${BASE_INSTALLER_URL}"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "${BASE_INSTALLER_URL}" "${BASE_INSTALLER}" <<'PYDL'
import sys
import urllib.request
url, out = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(url, timeout=60) as r:
    data = r.read()
open(out, "wb").write(data)
PYDL
  else
    echo "ERROR: se requiere curl, wget o python3 para descargar el instalador base."
    exit 1
  fi
  chmod +x "${BASE_INSTALLER}"
}

apply_remote_ssh_improvement() {
  local HORUS_DIR="/opt/horus"
  local SSH_WATCHER="${HORUS_DIR}/ssh_log_watcher.py"
  local HORUS_PY="${HORUS_DIR}/horus.py"
  local WRAPPER="/usr/local/bin/horus"
  local SERVICE="horus.service"

  echo "==> Integrando mejora SSH local + SSH remoto..."

  if [ ! -f "${HORUS_PY}" ]; then
    echo "ERROR: no existe ${HORUS_PY}. La instalacion base no finalizo correctamente."
    exit 1
  fi

  local VPN_NET_PREFIX
  VPN_NET_PREFIX="$(python3 - <<'PY'
import re
c=open('/opt/horus/horus.py', encoding='utf-8').read()
m=re.search(r'VPN_NET\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+\.)0/24"', c)
print(m.group(1) if m else '')
PY
)"

  if [ -z "${VPN_NET_PREFIX}" ]; then
    read -r -p "No pude detectar el prefijo VPN. Ingresa prefijo /24, ej 192.168.2.: " VPN_NET_PREFIX
  fi

  cp -a "${SSH_WATCHER}" "${SSH_WATCHER}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  cp -a "${HORUS_PY}" "${HORUS_PY}.bak.$(date +%Y%m%d%H%M%S)"
  [ -f "${WRAPPER}" ] && cp -a "${WRAPPER}" "${WRAPPER}.bak.$(date +%Y%m%d%H%M%S)" || true

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
        subprocess.run(
            ["journalctl", "-u", "sshd.service", "-n", "1", "--no-pager"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
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

    ip = m.group("ip")
    user = m.group("user")
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

    if dpt != "22":
        return
    if not src.startswith(VPN_NET_PREFIX):
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

  python3 - <<'PYHORUS_PATCH'
from pathlib import Path

p = Path('/opt/horus/horus.py')
s = p.read_text(encoding='utf-8')

if 'def filter_rule_exists(rule):' not in s:
    marker = '''def rule_exists(rule):\n    try:\n        subprocess.check_call(["iptables", "-t", "nat", "-C", "PREROUTING"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n        return True\n    except Exception:\n        return False\n'''
    insert = marker + '''\n\ndef filter_rule_exists(rule):\n    try:\n        subprocess.check_call(["iptables", "-C", "FORWARD"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n        return True\n    except Exception:\n        return False\n\n\ndef ssh_remote_rule():\n    return [\n        "-i", IF_IN,\n        "-s", VPN_NET,\n        "-p", "tcp",\n        "--dport", "22",\n        "-m", "conntrack",\n        "--ctstate", "NEW",\n        "-j", "LOG",\n        "--log-prefix", "HORUS_SSH_REMOTE ",\n        "--log-level", "4",\n    ]\n\n\ndef add_ssh_remote_logging():\n    rule = ssh_remote_rule()\n    try:\n        if not filter_rule_exists(rule):\n            run_cmd(["iptables", "-I", "FORWARD", "1"] + rule)\n    except Exception as e:\n        print("Error agregando regla SSH remoto:", e)\n\n\ndef del_ssh_remote_logging():\n    rule = ssh_remote_rule()\n    try:\n        while filter_rule_exists(rule):\n            run_cmd(["iptables", "-D", "FORWARD"] + rule)\n    except Exception as e:\n        print("Error borrando regla SSH remoto:", e)\n'''
    if marker not in s:
        raise SystemExit('No se encontro el bloque rule_exists esperado en /opt/horus/horus.py')
    s = s.replace(marker, insert)

add_block = '''    try:\n        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])\n    except Exception:\n        pass\n\ndef del_iptables():\n'''
if 'add_ssh_remote_logging()' not in s.split('def add_iptables():', 1)[1].split('def del_iptables():', 1)[0]:
    if add_block not in s:
        raise SystemExit('No se encontro el bloque sysctl esperado en add_iptables')
    s = s.replace(add_block, '''    add_ssh_remote_logging()\n    try:\n        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])\n    except Exception:\n        pass\n\ndef del_iptables():\n    del_ssh_remote_logging()\n''')

p.write_text(s, encoding='utf-8')
PYHORUS_PATCH

  if [ -f "${WRAPPER}" ]; then
    python3 - <<'PYWRAP_PATCH'
from pathlib import Path
p = Path('/usr/local/bin/horus')
s = p.read_text(encoding='utf-8')

if 'filter_rule_exists()' not in s:
    marker = 'rule_exists() { iptables -t nat -C PREROUTING "$@" >/dev/null 2>&1; }\n'
    insert = marker + r'''
filter_rule_exists() { iptables -C FORWARD "$@" >/dev/null 2>&1; }

del_ssh_remote_logging_rule() {
  load_horus_vars
  while filter_rule_exists -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 22 -m conntrack --ctstate NEW -j LOG --log-prefix "HORUS_SSH_REMOTE " --log-level 4; do
    iptables -D FORWARD -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 22 -m conntrack --ctstate NEW -j LOG --log-prefix "HORUS_SSH_REMOTE " --log-level 4 || true
  done
}
'''
    if marker in s:
        s = s.replace(marker, insert)

if 'purge_iptables() {' in s and 'del_ssh_remote_logging_rule' in s:
    s = s.replace('purge_iptables() {\n  load_horus_vars\n', 'purge_iptables() {\n  load_horus_vars\n  del_ssh_remote_logging_rule\n')

p.write_text(s, encoding='utf-8')
PYWRAP_PATCH
  fi

  chmod 644 "${SSH_WATCHER}"
  chmod 755 "${HORUS_PY}"
  [ -f "${WRAPPER}" ] && chmod 755 "${WRAPPER}" || true

  systemctl restart "${SERVICE}" || true
  echo "==> Mejora SSH integrada. Revisa: tail -f /var/log/horus/ssh_access.log"
}

download_base_installer
bash "${BASE_INSTALLER}"
apply_remote_ssh_improvement

echo
cat <<'EOF'
==== Instalacion Horus completada con mejora SSH remota ====

Eventos esperados en /var/log/horus/ssh_access.log:
- LOCAL_SSH  : conexiones SSH hacia la maquina Horus/VPN.
- REMOTE_SSH : conexiones SSH de clientes VPN hacia otras maquinas por TCP/22.

Comandos utiles:
  horus status
  horus logs
  tail -f /var/log/horus/ssh_access.log
EOF
