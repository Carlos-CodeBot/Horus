#!/usr/bin/env bash
# Instalador_Horus.sh (tu base + fixes: wrapper logs, uninstall fuerte, SSH dst, purga total)
# Ejecutar como root.

set -euo pipefail
IFS=$'\n\t'

HORUS_DIR="/opt/horus"
VENV_DIR="${HORUS_DIR}/venv"
MITM_ENTRY="${VENV_DIR}/bin/mitmdump"
MITMPROXY_PY="${VENV_DIR}/bin/python"
HORUS_SERVICE="/etc/systemd/system/horus.service"
CERT_PEM_DST="${HORUS_DIR}/mitmproxy-ca-cert.pem"
CERT_CER_DST="${HORUS_DIR}/mitmproxy-ca-cert.cer"
WRAPPER="/usr/local/bin/horus"
WRAPPER_PURGE="/usr/local/bin/horus-uninstall"
MITM_CONF_DIR="/root/.mitmproxy"
BOOTLOG="/root/mitmproxy_bootstrap.log"
LOG_DIR="/var/log/horus"

echo "==== Instalador Horus (full, logs en ${LOG_DIR}) ===="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script necesita permisos de root. Ejecuta con sudo."
  exit 1
fi

echo "Aviso: Asegúrate de tener autorización para interceptar TLS en las máquinas objetivo."

# ---------------------------
# 1) Dependencias
# ---------------------------
if command -v dnf >/dev/null 2>&1; then
  echo "==> Instalando dependencias con dnf..."
  dnf -y install python3 python3-virtualenv python3-pip python3-devel gcc \
                 openssl-devel libffi-devel redhat-rpm-config iptables iproute \
                 dos2unix glibc-langpack-en policycoreutils-python-utils || true
elif command -v apt-get >/dev/null 2>&1; then
  echo "==> Instalando dependencias con apt..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip python3-dev gcc \
                                                  libssl-dev libffi-dev iptables iproute2 dos2unix policycoreutils || true
  export LANG=en_US.UTF-8
  locale-gen en_US.UTF-8 || true
else
  echo "Gestor de paquetes no detectado. Instala python3, pip, openssl, iptables."
fi

# ---------------------------
# 2) Detectar interfaz/prefijo
# ---------------------------
detect_interface() {
  local IF
  IF=$(ip -o -4 addr show | awk '/tun|tap/ {print $2; exit}' || true)
  [ -n "$IF" ] && { echo "$IF"; return; }
  IF=$(ip -o -4 addr show | awk '!/ lo / {print $2 " " $4}' | awk '/^(tun|tap|eth|en|ens|wlan)/ {print $1; exit}' || true)
  [ -n "$IF" ] && { echo "$IF"; return; }
  echo ""
}
IF_IN="$(detect_interface)"
if [ -z "${IF_IN}" ]; then
  read -r -p "No se detectó interfaz tun/tap automáticamente. Ingresa la interfaz a usar [tun0]: " IF_IN
  IF_IN="${IF_IN:-tun0}"
else
  echo "Interfaz detectada: ${IF_IN}"
fi

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
  read -r -p "Prefijo /24 de la VPN (ej: 192.168.2.) [192.168.2.]: " TMP_PREFIX
  VPN_NET_PREFIX="${TMP_PREFIX:-192.168.2.}"
fi
echo "Usando interfaz ${IF_IN} y prefijo ${VPN_NET_PREFIX} (se formará ${VPN_NET_PREFIX}0/24)"

# ---------------------------
# 3) Preparar dirs + SELinux
# ---------------------------
mkdir -p "${HORUS_DIR}" "${LOG_DIR}"
chown -R root:root "${HORUS_DIR}" "${LOG_DIR}"
chmod 755 "${HORUS_DIR}" "${LOG_DIR}"

if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
  echo "SELinux Enforcing: ajustando contexto para ${LOG_DIR}..."
  command -v semanage >/dev/null 2>&1 || {
    command -v dnf >/dev/null 2>&1 && dnf -y install policycoreutils-python-utils || true
    command -v apt-get >/dev/null 2>&1 && apt-get -y install policycoreutils || true
  }
  if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t var_log_t '/var/log/horus(/.*)?' >/dev/null 2>&1 || true
    restorecon -Rv "${LOG_DIR}" || true
  fi
fi

# ---------------------------
# 4) Addons y módulos
# ---------------------------
cat > "${HORUS_DIR}/mitm_simple_logger.py" <<'PYMITM'
from mitmproxy import http, ctx
import datetime, os
OUTFILE = "/var/log/horus/http_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
def now(): return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
class SimpleLogger:
    def __init__(self):
        ctx.log.info(f"mitm_simple_logger logging to {OUTFILE}")
        open(OUTFILE, "a").close()
    def response(self, flow: http.HTTPFlow):
        try:
            cip = flow.client_conn.address[0] if flow.client_conn and getattr(flow.client_conn,"address",None) else ""
            m   = flow.request.method or "-"
            url = flow.request.pretty_url if getattr(flow.request,"pretty_url",None) else (flow.request.path or "-")
            sc  = flow.response.status_code if flow.response else "-"
            with open(OUTFILE, "a") as f:
                f.write(f"{now()}\t{cip}\t{m}\t{url}\t{sc}\n")
        except Exception as e:
            ctx.log.error(f"mitm_simple_logger error: {e}")
addons = [ SimpleLogger() ]
PYMITM

# watcher de journal sshd (Accepted/Failed)
printf 'VPN_NET_PREFIX = "%s"\n\n' "${VPN_NET_PREFIX}" > "${HORUS_DIR}/ssh_log_watcher.py"
cat >> "${HORUS_DIR}/ssh_log_watcher.py" <<'PYSSH'
import re, subprocess, os, datetime
OUTFILE = "/var/log/horus/ssh_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
open(OUTFILE, "a").close()
RE_ACC = re.compile(r"Accepted .* for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_FAIL= re.compile(r"Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
def now(): return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def run():
    use_j = True
    try:
        subprocess.run(["journalctl","-u","sshd.service","-n","1","--no-pager"],check=True,stdout=subprocess.DEVNULL)
    except Exception:
        use_j = False
    cmd = ["journalctl","-u","sshd.service","-f","-o","short"] if use_j else ["tail","-F","/var/log/auth.log"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    try:
        for line in p.stdout:
            m = RE_ACC.search(line) or RE_FAIL.search(line)
            if not m: continue
            ip, user = m.group("ip"), m.group("user")
            if not ip.startswith(VPN_NET_PREFIX): continue
            ev = "ACCEPTED" if "Accepted " in line else "FAILED"
            with open(OUTFILE,"a") as f:
                f.write(f"{now()}\t{ip}\t{ev}\t{user}\t{line.strip()}\n")
    except KeyboardInterrupt:
        p.terminate()
if __name__ == "__main__": run()
PYSSH

# flow sniffer IP/TCP/UDP general
cat > "${HORUS_DIR}/flow_sniffer.py" <<'PYSNIFF'
#!/usr/bin/env python3
import os, sys, csv
from datetime import datetime
try:
    from scapy.all import sniff, IP, TCP, UDP
except Exception:
    print("ERROR: falta scapy en venv. Instala con /opt/horus/venv/bin/pip install scapy")
    sys.exit(2)
LOG_CSV = "/var/log/horus/flows.csv"
IFACE = os.environ.get("HORUS_IFACE","tun0")
os.makedirs(os.path.dirname(LOG_CSV), exist_ok=True)
if not os.path.exists(LOG_CSV):
    with open(LOG_CSV,"w",newline="") as f: csv.writer(f).writerow(["timestamp","src_ip","dst_ip","dst_port","protocol"])
def now(): return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
def handle(pkt):
    if not pkt.haslayer(IP): return
    if pkt.haslayer(TCP):
        proto, dport = "TCP", pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto, dport = "UDP", pkt[UDP].dport
    else: return
    with open(LOG_CSV,"a",newline="") as f:
        csv.writer(f).writerow([now(), pkt[IP].src, pkt[IP].dst, str(dport), proto])
def main():
    iface = sys.argv[1] if len(sys.argv)>1 else IFACE
    sniff(iface=iface, filter="ip and (tcp or udp)", prn=handle, store=False)
if __name__=="__main__": main()
PYSNIFF
chmod 755 "${HORUS_DIR}/flow_sniffer.py"

# NUEVO: sniffer específico de SSH (SYN -> 22) para origen/destino en el mismo ssh_access.log
cat > "${HORUS_DIR}/ssh_flow_sniffer.py" <<'PYSSHF'
#!/usr/bin/env python3
import os, sys
from datetime import datetime
try:
    from scapy.all import sniff, IP, TCP
except Exception:
    print("ERROR: falta scapy. /opt/horus/venv/bin/pip install scapy")
    sys.exit(2)
OUTFILE = "/var/log/horus/ssh_access.log"
IFACE = os.environ.get("HORUS_IFACE","tun0")
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
open(OUTFILE,"a").close()
def now(): return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def is_syn(pkt): 
    try: return pkt[TCP].flags & 0x02 and not (pkt[TCP].flags & 0x10)
    except Exception: return False
def handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): return
    if pkt[TCP].dport != 22: return
    if not is_syn(pkt): return
    with open(OUTFILE,"a") as f:
        f.write(f"{now()}\tFLOW\t{pkt[IP].src}\t{pkt[IP].dst}\t22\tTCP\n")
def main():
    iface = sys.argv[1] if len(sys.argv)>1 else IFACE
    sniff(iface=iface, filter="tcp port 22", prn=handle, store=False)
if __name__=="__main__": main()
PYSSHF
chmod 755 "${HORUS_DIR}/ssh_flow_sniffer.py"

# ---------------------------
# 5) horus.py (arranca 3 procesos + ssh flow)
# ---------------------------
printf 'IF_IN = "%s"\nVPN_NET = "%s0/24"\nMITM_ADDON = "%s"\nMITM_PORT = 8080\nMITMDUMP_BIN = "%s"\nCERT_PATH = "%s"\nCERT_PATH_WIN = "%s"\nSSH_WATCHER = "%s"\nFLOW_SNIFFER = "%s"\nSSH_FLOW_SNIFFER = "%s"\nHTTP_LOG = "%s/http_access.log"\nSSH_LOG = "%s/ssh_access.log"\nFLOW_LOG = "%s/flows.csv"\n\n' \
  "${IF_IN}" "${VPN_NET_PREFIX}" "${HORUS_DIR}/mitm_simple_logger.py" "${MITM_ENTRY}" "${CERT_PEM_DST}" "${CERT_CER_DST}" "${HORUS_DIR}/ssh_log_watcher.py" "${HORUS_DIR}/flow_sniffer.py" "${HORUS_DIR}/ssh_flow_sniffer.py" "${LOG_DIR}" "${LOG_DIR}" "${LOG_DIR}" > "${HORUS_DIR}/horus.py"

cat >> "${HORUS_DIR}/horus.py" <<'PYHORUS'
#!/usr/bin/env python3
import subprocess, signal, time, os, sys
def print_banner():
    print(r"""
  _   _   ____   _   _   ____   _____ 
 | | | | / ___| | | | | / ___| | ____|
 | | | || |  _  | | | | \___ \ |  _|  
 | |_| || |_| | | |_| |  ___) || |___ 
  \___/  \____|  \___/  |____/ |_____|
      _      ____  _   _  _____ 
           .--.
         .'_\/_'.
        '. /\ /.'     ,--.
          "||"       /    \
         _.'  '._    \\    /
       .'  .--.  '.   `--'
      /   (    )   \
""")
    print("Horus iniciado. Cert PEM:", CERT_PATH)
    print("Cert CER (Windows):", CERT_PATH_WIN, "\n")
def check_root():
    if os.geteuid() != 0:
        print("Horus necesita ejecutarse como root."); sys.exit(1)
def run_cmd(cmd):
    try: return subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print("Comando falló:", e); return e.returncode
def add_iptables():
    try: run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","80","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception: pass
    try: run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","443","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception: pass
    try: run_cmd(["sysctl","-w","net.ipv4.ip_forward=1"])
    except Exception: pass
def rule_exists(rule):
    try:
        subprocess.check_call(["iptables","-t","nat","-C","PREROUTING"]+rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception: return False
def del_iptables():
    r1=["-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","80","-j","REDIRECT","--to-ports",str(MITM_PORT)]
    r2=["-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","443","-j","REDIRECT","--to-ports",str(MITM_PORT)]
    try:
        if rule_exists(r1): run_cmd(["iptables","-t","nat","-D","PREROUTING"]+r1)
    except Exception as e: print("Error borrando regla 80:", e)
    try:
        if rule_exists(r2): run_cmd(["iptables","-t","nat","-D","PREROUTING"]+r2)
    except Exception as e: print("Error borrando regla 443:", e)
def start_mitmdump():
    if os.path.exists(MITMDUMP_BIN):
        return subprocess.Popen([MITMDUMP_BIN,"--mode","transparent","--listen-port",str(MITM_PORT),"-s",MITM_ADDON])
    return subprocess.Popen(["mitmdump","--mode","transparent","--listen-port",str(MITM_PORT),"-s",MITM_ADDON])
def start_py(mod):
    vpy = os.path.join(os.path.dirname(MITMDUMP_BIN), "python")
    if os.path.exists(vpy): return subprocess.Popen([vpy, mod])
    return subprocess.Popen(["python3", mod])
def main():
    check_root(); print_banner()
    print("Interfaz:", IF_IN, "VPN:", VPN_NET)
    for p in (HTTP_LOG,SSH_LOG,FLOW_LOG):
        os.makedirs(os.path.dirname(p), exist_ok=True); open(p,"a").close()
    add_iptables()
    procs = [
        start_mitmdump(),
        start_py(SSH_WATCHER),
        start_py(FLOW_SNIFFER),
        start_py(SSH_FLOW_SNIFFER)
    ]
    def shutdown(*_):
        for pr in procs:
            try: pr.terminate()
            except Exception: pass
        time.sleep(1); del_iptables(); sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        while True:
            dead=[p for p in procs if p.poll() is not None]
            if dead:
                print("Subproceso terminó, cerrando Horus."); break
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()
if __name__ == "__main__": main()
PYHORUS

# Asegurar shebang + CRLF
if ! head -n1 "${HORUS_DIR}/horus.py" | grep -q '^#!'; then
  sed -i '1i #!/usr/bin/env python3' "${HORUS_DIR}/horus.py"
fi
command -v dos2unix >/dev/null 2>&1 && dos2unix "${HORUS_DIR}/horus.py" || true
chmod 755 "${HORUS_DIR}/horus.py"
chmod 644 "${HORUS_DIR}/mitm_simple_logger.py" "${HORUS_DIR}/ssh_log_watcher.py"

# ---------------------------
# 6) venv + paquetes
# ---------------------------
echo "==> Creando venv en ${VENV_DIR} e instalando mitmproxy+scapy (puede tardar)..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
"${VENV_DIR}/bin/pip" install mitmproxy scapy >/dev/null || true

# ---------------------------
# 7) CA: mitmproxy bootstrap -> fallback OpenSSL
# ---------------------------
echo
echo "===== OPCIÓN CA ====="
echo "1) Generar CA automáticamente (recomendado)"
echo "2) Usar CA + KEY existentes (tú entregas rutas absolutas)"
read -r -p "Selecciona 1 o 2 [1]: " CA_CHOICE
CA_CHOICE="${CA_CHOICE:-1}"

mkdir -p "${MITM_CONF_DIR}"
if [ "${CA_CHOICE}" = "1" ]; then
  echo "==> Intentando generar CA con mitmproxy (bootstrap forzado)..."
  export HOME=/root LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
  rm -f "${BOOTLOG}" || true
  if [ -x "${MITM_ENTRY}" ]; then
    "${MITM_ENTRY}" --set confdir="${MITM_CONF_DIR}" --listen-port 0 -s /dev/null -q > "${BOOTLOG}" 2>&1 &
  else
    "${MITMPROXY_PY}" -m mitmproxy.tools.dump --set confdir="${MITM_CONF_DIR}" --listen-port 0 -s /dev/null -q > "${BOOTLOG}" 2>&1 &
  fi
  MPID=$!
  for _ in {1..10}; do sleep 1; [ -f "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" ] && break; done
  kill ${MPID} >/dev/null 2>&1 || true; wait ${MPID} 2>/dev/null || true
  if [ -f "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" ]; then
    cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"; chmod 644 "${CERT_PEM_DST}"
    command -v openssl >/dev/null 2>&1 && openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
    chmod 644 "${CERT_CER_DST}" || true
  else
    echo "WARNING: mitmproxy no generó CA. Usando fallback OpenSSL..."
    set -eux
    openssl genrsa -out "${MITM_CONF_DIR}/mitmproxy-ca.key" 4096
    openssl req -x509 -new -nodes -key "${MITM_CONF_DIR}/mitmproxy-ca.key" \
      -sha256 -days 3650 \
      -subj "/C=CO/O=Horus/OU=Monitoring/CN=Horus MITM Root CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" \
      -addext "authorityKeyIdentifier=keyid:always,issuer:always" \
      -out "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
    cat "${MITM_CONF_DIR}/mitmproxy-ca.key" "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" > "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    chmod 600 "${MITM_CONF_DIR}/mitmproxy-ca.key" "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    chmod 644 "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
    cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"; chmod 644 "${CERT_PEM_DST}"
    command -v openssl >/dev/null 2>&1 && openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
    chmod 644 "${CERT_CER_DST}" || true
    set +eux
  fi
else
  echo "==> Usar CA existente"
  read -r -p "CERT PEM (CA o PEM combinado) [/root/my-ca.pem]: " USER_CERT
  USER_CERT="${USER_CERT:-/root/my-ca.pem}"
  read -r -p "KEY (si el CERT no incluye la KEY) [/root/my-ca.key]: " USER_KEY
  USER_KEY="${USER_KEY:-}"
  [ -f "${USER_CERT}" ] || { echo "ERROR: no existe ${USER_CERT}"; exit 1; }
  [ -z "${USER_KEY}" ] || [ -f "${USER_KEY}" ] || { echo "ERROR: no existe ${USER_KEY}"; exit 1; }
  if ! openssl x509 -in "${USER_CERT}" -noout -text >/tmp/_horus_cert.txt 2>/dev/null; then
    echo "ERROR: no se pudo leer ${USER_CERT}"; exit 1
  fi
  grep -q "CA:TRUE" /tmp/_horus_cert.txt || { echo "ERROR: NO es una CA (wildcard de web no sirve)."; exit 1; }
  if grep -q "PRIVATE KEY" "${USER_CERT}" 2>/dev/null; then
    cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    awk '/-----BEGIN CERTIFICATE-----/{f=1}f{print}/-----END CERTIFICATE-----/{exit}' "${USER_CERT}" > "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" || cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
  else
    [ -n "${USER_KEY}" ] || { echo "ERROR: certificado sin KEY."; exit 1; }
    cat "${USER_KEY}" "${USER_CERT}" > "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
  fi
  chmod 600 "${MITM_CONF_DIR}/mitmproxy-ca.pem" || true
  chmod 644 "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" || true
  cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"; chmod 644 "${CERT_PEM_DST}"
  command -v openssl >/dev/null 2>&1 && openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
  chmod 644 "${CERT_CER_DST}" || true
fi

# ---------------------------
# 8) systemd unit y arranque
# ---------------------------
cat > "${HORUS_SERVICE}" <<'EOF'
[Unit]
Description=Horus - simple VPN HTTP+SSH tracer (mitm + ssh watcher + flow sniffer)
After=network.target

[Service]
Type=simple
ExecStart=/opt/horus/horus.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${HORUS_SERVICE}"
systemctl daemon-reload
systemctl enable --now horus.service || true

# ---------------------------
# 9) Wrapper (arregla rutas de logs + uninstall fuerte)
# ---------------------------
cat > /usr/local/bin/horus <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail

HORUS_SERVICE="horus.service"
HORUS_DIR="/opt/horus"
LOG_DIR="/var/log/horus"
CERT_PEM="${HORUS_DIR}/mitmproxy-ca-cert.pem"   # Linux/macOS/Firefox usa PEM
CERT_CER="${HORUS_DIR}/mitmproxy-ca-cert.cer"   # Windows usa CER (DER)

print_help() {
  cat <<'HHELP'
horus — wrapper para el servicio Horus

Uso:
  horus start         Inicia el servicio
  horus stop          Detiene el servicio
  horus restart       Reinicia el servicio y muestra status
  horus status        Muestra estado del servicio
  horus logs          Muestra últimos 200 de HTTP y SSH
  horus flows         Muestra últimos 200 de flows.csv
  horus certpath      Muestra rutas de certificados (Windows y Linux/macOS)
  horus install-cert /ruta/al/mitmproxy-ca-cert.cer   Copia un .cer al dir de Horus
  horus uninstall     Desinstala COMPLETAMENTE Horus (purga total)
  horus help|-h       Esta ayuda
HHELP
}

purge_iptables() {
  # Lee IF_IN, VPN_NET y MITM_PORT desde /opt/horus/horus.py
  local IF_IN VPN_NET MITM_PORT
  IF_IN=$(python3 - <<'PY'
import re; c=open("/opt/horus/horus.py").read()
m=re.search(r'IF_IN\s*=\s*"([^"]+)"',c); print(m.group(1) if m else "tun0")
PY
)
  VPN_NET=$(python3 - <<'PY'
import re; c=open("/opt/horus/horus.py").read()
m=re.search(r'VPN_NET\s*=\s*"([^"]+)"',c); print(m.group(1) if m else "10.38.0.0/24")
PY
)
  MITM_PORT=$(python3 - <<'PY'
import re; c=open("/opt/horus/horus.py").read()
m=re.search(r'MITM_PORT\s*=\s*(\d+)',c); print(m.group(1) if m else "8080")
PY
)

  # Sin arrays (compatible sh/bash)
  iptables -t nat -C PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 80  -j REDIRECT --to-ports "$MITM_PORT" >/dev/null 2>&1 \
    && iptables -t nat -D PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 80  -j REDIRECT --to-ports "$MITM_PORT" || true

  iptables -t nat -C PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT" >/dev/null 2>&1 \
    && iptables -t nat -D PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport 443 -j REDIRECT --to-ports "$MITM_PORT" || true
}

do_uninstall() {
  echo "[*] Deteniendo servicio..."
  systemctl stop "${HORUS_SERVICE}" || true
  systemctl disable "${HORUS_SERVICE}" || true

  echo "[*] Matando procesos residuales..."
  pkill -f "/opt/horus/venv/bin/mitmdump" 2>/dev/null || true
  pkill -f "/opt/horus/ssh_log_watcher.py" 2>/dev/null || true
  pkill -f "/opt/horus/ssh_flow_sniffer.py" 2>/dev/null || true
  pkill -f "/opt/horus/flow_sniffer.py" 2>/dev/null || true
  pkill -f "/opt/horus/horus.py" 2>/dev/null || true

  echo "[*] Quitando reglas NAT (iptables)..."
  purge_iptables

  echo "[*] Eliminando unit y recargando systemd..."
  rm -f /etc/systemd/system/horus.service
  systemctl daemon-reload

  echo "[*] Eliminando archivos y logs..."
  rm -rf /opt/horus /var/log/horus /root/.mitmproxy

  echo "[*] Eliminando wrapper/symlink y PATH..."
  rm -f /usr/local/bin/horus /usr/bin/horus /usr/local/bin/horus-uninstall /etc/profile.d/horus_path.sh

  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    command -v semanage >/dev/null 2>&1 && semanage fcontext -d '/var/log/horus(/.*)?' 2>/dev/null || true
    restorecon -Rv /var/log >/dev/null 2>&1 || true
  fi

  echo "Horus desinstalado COMPLETAMENTE."
}

case "${1:-help}" in
  start)    systemctl start ${HORUS_SERVICE}; systemctl status ${HORUS_SERVICE} --no-pager ;;
  stop)     systemctl stop ${HORUS_SERVICE} ;;
  restart)  systemctl restart ${HORUS_SERVICE}; systemctl status ${HORUS_SERVICE} --no-pager ;;
  status)   systemctl status ${HORUS_SERVICE} --no-pager ;;
  logs)
    echo "=== HTTP ===";  tail -n 200 "${LOG_DIR}/http_access.log" 2>/dev/null || echo "No hay http_access.log"
    echo "=== SSH  ===";  tail -n 200 "${LOG_DIR}/ssh_access.log"  2>/dev/null || echo "No hay ssh_access.log"
    ;;
  flows)    tail -n 200 "${LOG_DIR}/flows.csv" 2>/dev/null || echo "No hay flows.csv" ;;
  certpath)
    echo "Windows (CER/DER): ${CERT_CER}"
    echo "Linux/macOS/Firefox (PEM): ${CERT_PEM}"
    ;;
  install-cert)
    if [ -z "${2:-}" ]; then echo "Uso: horus install-cert /ruta/al/mitmproxy-ca-cert.cer"; exit 2; fi
    cp "$2" "${CERT_CER}" && chmod 644 "${CERT_CER}" && echo "Cert copiado a ${CERT_CER}"
    ;;
  uninstall) do_uninstall ;;
  help|--help|-h|*) print_help ;;
esac
WRAP

# garantizar formato y permisos
chmod +x /usr/local/bin/horus
command -v dos2unix >/dev/null 2>&1 && dos2unix /usr/local/bin/horus || true
ln -sf /usr/local/bin/horus /usr/bin/horus


# desinstalador standalone
cat > "${WRAPPER_PURGE}" <<'PURGE'
#!/usr/bin/env bash
exec /usr/local/bin/horus uninstall
PURGE
chmod 755 "${WRAPPER_PURGE}"

# ---------------------------
# 10) Final
# ---------------------------
echo "==== Instalación completada ===="
echo " - Horus instalado en: ${HORUS_DIR}"
echo " - Servicio systemd: horus.service"
echo " - Wrapper: ${WRAPPER} (usa 'horus -h') y symlink /usr/bin/horus"
echo " - Logs: ${LOG_DIR}/http_access.log, ${LOG_DIR}/ssh_access.log, ${LOG_DIR}/flows.csv"
echo
echo "Certificados para distribuir a los clientes VPN:"
echo " - Windows (formato CER/DER): ${CERT_CER_DST}"
echo " - Linux/macOS/Firefox (formato PEM): ${CERT_PEM_DST}"
echo
echo "Instala el CERT correspondiente como 'Autoridad de certificación raíz de confianza' y reinicia el navegador."
systemctl status horus --no-pager -l || true
journalctl -u horus -n 50 --no-pager -l || true
