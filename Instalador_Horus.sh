#!/usr/bin/env bash
# install_horus_rocky_complete.sh
# Instalador Horus (Rocky-ready) — versión completa y corregida.
# Ejecutar como root:
# sudo bash install_horus_rocky_complete.sh

set -euo pipefail

HORUS_DIR="/opt/horus"
VENV_DIR="${HORUS_DIR}/venv"
MITM_ENTRY="${VENV_DIR}/bin/mitmdump"
MITMPROXY_PY="${VENV_DIR}/bin/python"
HORUS_SERVICE="/etc/systemd/system/horus.service"
CERT_PEM_DST="${HORUS_DIR}/mitmproxy-ca-cert.pem"
CERT_CER_DST="${HORUS_DIR}/mitmproxy-ca-cert.cer"

echo "==== Instalador Horus (complete & fixed) ===="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script necesita permisos de root. Ejecuta con sudo."
  exit 1
fi

# 0) Instalar dependencias (dnf/apt)
if command -v dnf >/dev/null 2>&1; then
  echo "==> Usando dnf para instalar dependencias"
  dnf -y install python3 python3-virtualenv python3-pip python3-devel gcc openssl-devel libffi-devel redhat-rpm-config iptables iproute || true
elif command -v apt-get >/dev/null 2>&1; then
  echo "==> Usando apt para instalar dependencias"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip python3-dev gcc libssl-dev libffi-dev iptables iproute2 || true
else
  echo "Gestor de paquetes no detectado. Asegúrate de tener python3, pip, openssl e iptables instalados."
fi

# 1) Detect interface tun/tap, else ask user
detect_interface() {
  IF_FOUND=$(ip -o -4 addr show | awk '/tun|tap/ {print $2; exit}' || true)
  if [ -n "${IF_FOUND}" ]; then echo "${IF_FOUND}"; return; fi
  IF_FOUND=$(ip -o -4 addr show | awk '!/ lo / {print $2 " " $4}' | awk '/^(tun|tap|eth|en|ens|wlan)/ {print $1; exit}' || true)
  if [ -n "${IF_FOUND}" ]; then echo "${IF_FOUND}"; return; fi
  echo ""
}

IF_IN="$(detect_interface)"
if [ -z "${IF_IN}" ]; then
  read -r -p "No se detectó interfaz tun/tap automáticamente. Ingresa la interfaz a usar [tun0]: " IF_IN
  IF_IN="${IF_IN:-tun0}"
else
  echo "Interfaz detectada: ${IF_IN}"
fi

# 2) Detect IP on interface to derive prefix; else ask user for prefix (e.g., 192.168.2.)
IP_ADDR="$(ip -o -4 addr show dev "${IF_IN}" 2>/dev/null | awk '{print $4}' | cut -d'/' -f1 || true)"
if [ -n "${IP_ADDR}" ]; then
  IFS='.' read -r o1 o2 o3 o4 <<< "${IP_ADDR}" || true
  if [[ "${o1}" =~ ^[0-9]+$ ]]; then
    VPN_NET_PREFIX="${o1}.${o2}.${o3}."
    echo "IP en ${IF_IN}: ${IP_ADDR} -> prefijo detectado: ${VPN_NET_PREFIX}"
  else
    VPN_NET_PREFIX=""
  fi
else
  VPN_NET_PREFIX=""
fi

if [ -z "${VPN_NET_PREFIX}" ]; then
  read -r -p "Ingresa el prefijo IP de la /24 de la VPN (ej: 192.168.2.) [192.168.2.]: " TMP_PREFIX
  VPN_NET_PREFIX="${TMP_PREFIX:-192.168.2.}"
fi

echo "Usando interfaz ${IF_IN} y prefijo ${VPN_NET_PREFIX} (se formará ${VPN_NET_PREFIX}0/24)"

# 3) Crear carpeta /opt/horus
mkdir -p "${HORUS_DIR}"
chown root:root "${HORUS_DIR}"
chmod 755 "${HORUS_DIR}"

# 4) Escribir mitm_simple_logger.py (literal)
cat > "${HORUS_DIR}/mitm_simple_logger.py" <<'PYMITM'
# mitm_simple_logger.py
# Addon para mitmdump que guarda líneas simples: ts,client_ip,method,path,status
from mitmproxy import http, ctx
import datetime, os

OUTFILE = "/opt/horus/http_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

class SimpleLogger:
    def __init__(self):
        ctx.log.info("mitm_simple_logger initialized; logging to %s" % OUTFILE)
        open(OUTFILE, "a").close()

    def response(self, flow: http.HTTPFlow):
        try:
            client_ip = ""
            if flow.client_conn and getattr(flow.client_conn, "address", None):
                client_ip = flow.client_conn.address[0]
            method = flow.request.method or "-"
            path = flow.request.pretty_url if getattr(flow.request, "pretty_url", None) else (flow.request.path or "-")
            status = flow.response.status_code if flow.response else "-"
            line = f"{now()}\t{client_ip}\t{method}\t{path}\t{status}\n"
            with open(OUTFILE, "a") as f:
                f.write(line)
        except Exception as e:
            ctx.log.error(f"mitm_simple_logger error: {e}")

addons = [ SimpleLogger() ]
PYMITM

# 5) Escribir ssh_log_watcher.py — captura SSH local y conexiones SSH remotas que atraviesan la VPN
printf 'VPN_NET_PREFIX = "%s"\n\n' "${VPN_NET_PREFIX}" > "${HORUS_DIR}/ssh_log_watcher.py"
cat >> "${HORUS_DIR}/ssh_log_watcher.py" <<'PYSSH'
# ssh_log_watcher.py
# Registra autenticaciones SSH locales y conexiones TCP/22 que atraviesan Horus por la VPN.
import datetime
import os
import queue
import re
import subprocess
import threading

OUTFILE = "/opt/horus/ssh_access.log"
REMOTE_PREFIX = "HORUS_SSH_REMOTE"

os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
LOGFH = open(OUTFILE, "a", buffering=1)

RE_ACCEPT = re.compile(r"Accepted .* for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_FAILED = re.compile(r"Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
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
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
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
            ["journalctl", "-u", "sshd.service", "--no-pager", "-n", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
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

    write_event(f"{now()}\t-\tERROR\t-\tWATCHER\tNo se pudo abrir una fuente de logs kernel para REMOTE_SSH")


def parse_local_ssh(line):
    m = RE_ACCEPT.search(line) or RE_FAILED.search(line)
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


def run_forever():
    start_local_ssh_stream()
    start_remote_ssh_stream()

    while True:
        source, line = event_queue.get()
        if source == "local_ssh":
            parse_local_ssh(line)
        elif source == "remote_ssh":
            parse_remote_ssh(line)


if __name__ == "__main__":
    run_forever()
PYSSH

# 6) Escribir horus.py — inyectamos IF_IN, VPN_NET y rutas de cert de forma segura
printf 'IF_IN = "%s"\nVPN_NET = "%s0/24"\nMITM_ADDON = "%s"\nMITM_PORT = 8080\nMITMDUMP_BIN = "%s"\nCERT_PATH = "%s"\nCERT_PATH_WIN = "%s"\nSSH_WATCHER = "%s"\nHTTP_LOG = "/opt/horus/http_access.log"\nSSH_LOG = "/opt/horus/ssh_access.log"\n\n' \
  "${IF_IN}" "${VPN_NET_PREFIX}" "${HORUS_DIR}/mitm_simple_logger.py" "${MITM_ENTRY}" "${CERT_PEM_DST}" "${CERT_CER_DST}" "${HORUS_DIR}/ssh_log_watcher.py" > "${HORUS_DIR}/horus.py"

cat >> "${HORUS_DIR}/horus.py" <<'PYHORUS_BODY'
#!/usr/bin/env python3
# horus.py: arranca mitmdump con el addon y el watcher SSH; instala reglas iptables y limpia al salir
import subprocess, signal, time, os, sys

def print_banner():
    banner = r"""
  _   _   ____   _   _   ____   _____ 
 | | | | / ___| | | | | / ___| | ____|
 | | | || |  _  | | | | \___ \ |  _|  
 | |_| || |_| | | |_| |  ___) || |___ 
  \___/  \____|  \___/  |____/ |_____|
      _      ____  _   _  _____ 
"""
    eye = r"""
           .--.
         .'_\/_'.
        '. /\ /.'     ,--.
          "||"       /    \
         _.'  '._    \\    /
       .'  .--.  '.   `--'
      /   (    )   \
"""
    print(banner)
    print(eye)
    print("Horus iniciado. Cert PEM:", CERT_PATH)
    print("Cert CER (Windows):", CERT_PATH_WIN)
    print()

def check_root():
    if os.geteuid() != 0:
        print("Horus necesita ejecutarse como root.")
        sys.exit(1)

def run_cmd(cmd):
    try:
        print("CMD:", " ".join(cmd))
        return subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print("Comando falló:", e)
        return e.returncode

def nat_rule_exists(rule):
    try:
        subprocess.check_call(["iptables", "-t", "nat", "-C", "PREROUTING"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def filter_rule_exists(rule):
    try:
        subprocess.check_call(["iptables", "-C", "FORWARD"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def add_ssh_remote_logging():
    rule = [
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
    try:
        if not filter_rule_exists(rule):
            run_cmd(["iptables", "-I", "FORWARD", "1"] + rule)
    except Exception as e:
        print("Error agregando regla SSH remoto:", e)

def del_ssh_remote_logging():
    rule = [
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
    try:
        while filter_rule_exists(rule):
            run_cmd(["iptables", "-D", "FORWARD"] + rule)
    except Exception as e:
        print("Error borrando regla SSH remoto:", e)

def add_iptables():
    try:
        run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","80","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception:
        pass
    try:
        run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","443","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception:
        pass
    add_ssh_remote_logging()
    try:
        run_cmd(["sysctl","-w","net.ipv4.ip_forward=1"])
    except Exception:
        pass

def del_iptables():
    del_ssh_remote_logging()
    rule1 = ["-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)]
    rule2 = ["-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)]
    try:
        if nat_rule_exists(rule1):
            run_cmd(["iptables","-t","nat","-D","PREROUTING"] + rule1)
    except Exception as e:
        print("Error borrando regla 80:", e)
    try:
        if nat_rule_exists(rule2):
            run_cmd(["iptables","-t","nat","-D","PREROUTING"] + rule2)
    except Exception as e:
        print("Error borrando regla 443:", e)

# start mitmdump: try entrypoint, fallback to python -m
def start_mitmdump():
    if os.path.exists(MITMDUMP_BIN):
        return subprocess.Popen([MITMDUMP_BIN, "--mode", "transparent", "--listen-port", str(MITM_PORT), "-s", MITM_ADDON])
    py = sys.executable
    try:
        return subprocess.Popen([py, "-m", "mitmproxy.tools.dump", "--mode", "transparent", "--listen-port", str(MITM_PORT), "-s", MITM_ADDON])
    except Exception:
        return subprocess.Popen(["mitmdump", "--mode", "transparent", "--listen-port", str(MITM_PORT), "-s", MITM_ADDON])

def start_ssh_watcher():
    vpy = os.path.join(os.path.dirname(MITMDUMP_BIN), "python")
    if os.path.exists(vpy):
        return subprocess.Popen([vpy, SSH_WATCHER])
    return subprocess.Popen(["python3", SSH_WATCHER])

def main():
    check_root()
    print_banner()
    print("Interfaz:", IF_IN, "  VPN:", VPN_NET)
    add_iptables()
    mitm_proc = start_mitmdump()
    ssh_proc = start_ssh_watcher()

    def shutdown(signum, frame):
        print("Horus: señal de salida recibida, deteniendo servicios...")
        try:
            mitm_proc.terminate()
        except Exception:
            pass
        try:
            ssh_proc.terminate()
        except Exception:
            pass
        time.sleep(1)
        del_iptables()
        print("Horus: limpieza finalizada.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    open(HTTP_LOG, "a").close()
    open(SSH_LOG, "a").close()

    try:
        while True:
            if mitm_proc.poll() is not None:
                print("mitmdump terminó con código", mitm_proc.returncode)
                break
            if ssh_proc.poll() is not None:
                print("ssh watcher terminó con código", ssh_proc.returncode)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)
    finally:
        del_iptables()

if __name__ == "__main__":
    main()
PYHORUS_BODY

# 7) Permisos
chmod 644 "${HORUS_DIR}/mitm_simple_logger.py" "${HORUS_DIR}/ssh_log_watcher.py"
chmod 755 "${HORUS_DIR}/horus.py"

# 8) Crear venv e instalar mitmproxy (silencioso)
echo "==> Creando venv en ${VENV_DIR} e instalando mitmproxy (esto puede tardar)..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
"${VENV_DIR}/bin/pip" install mitmproxy >/dev/null || true

# 9) Generar CA sin UI usando python -m mitmproxy.tools.dump (arrancar brevemente en background)
echo "==> Generando CA de mitmproxy (sin UI)..."
if [ -x "${MITM_ENTRY}" ]; then
  "${MITM_ENTRY}" --quiet --listen-port 0 -s /dev/null >/dev/null 2>&1 &
  MPID=$!
else
  "${MITMPROXY_PY}" -m mitmproxy.tools.dump --quiet --listen-port 0 -s /dev/null >/dev/null 2>&1 &
  MPID=$!
fi
sleep 3
kill ${MPID} >/dev/null 2>&1 || true
wait ${MPID} 2>/dev/null || true

# copiar CA a /opt/horus y crear .cer (DER) para Windows
if [ -f /root/.mitmproxy/mitmproxy-ca-cert.pem ]; then
  cp /root/.mitmproxy/mitmproxy-ca-cert.pem "${CERT_PEM_DST}"
  chmod 644 "${CERT_PEM_DST}"
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
    chmod 644 "${CERT_CER_DST}" || true
  fi
  echo "==> Copiado certificado CA a: ${CERT_PEM_DST}"
else
  echo "WARNING: No se encontró /root/.mitmproxy/mitmproxy-ca-cert.pem. Si no se generó, ejecuta '${MITMPROXY_PY} -m mitmproxy.tools.dump' manualmente."
fi

# 10) Crear systemd service (con rutas expandidas)
cat > "${HORUS_SERVICE}" <<EOF
[Unit]
Description=Horus - simple VPN HTTP+SSH tracer (mitm + ssh watcher)
After=network.target

[Service]
Type=simple
ExecStart=${HORUS_DIR}/horus.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${HORUS_SERVICE}"

# 11) Recargar systemd y habilitar servicio
echo "==> Recargando systemd..."
systemctl daemon-reload

echo "==> Habilitando y arrancando servicio horus..."
systemctl enable --now horus.service || true

echo "==== Instalación completada ===="
echo " - Horus instalado en: ${HORUS_DIR}"
echo " - Servicio: horus.service"
echo " - Cert PEM: ${CERT_PEM_DST}"
echo " - Cert CER (Windows DER): ${CERT_CER_DST} (si se generó)"
echo "Logs:"
echo " tail -f ${HORUS_DIR}/http_access.log"
echo " tail -f ${HORUS_DIR}/ssh_access.log"

echo
echo "IMPORTANTE:"
echo " - Instala ${CERT_PEM_DST} (o ${CERT_CER_DST} para Windows) en cada cliente VPN para que HTTPS sea interceptado correctamente."
echo " - Asegúrate de tener autorización para interceptar tráfico TLS."