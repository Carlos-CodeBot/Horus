#!/usr/bin/env bash
# Instalador_Horus.sh (original + Flow Sniffer)
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
# 1) instalar dependencias
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
  echo "Gestor de paquetes no detectado. Asegúrate de tener python3, pip, openssl, iptables instalados."
fi

# ---------------------------
# 2) detectar interfaz/prefijo
# ---------------------------
detect_interface() {
  local IF
  IF=$(ip -o -4 addr show | awk '/tun|tap/ {print $2; exit}' || true)
  if [ -n "$IF" ]; then echo "$IF"; return; fi
  IF=$(ip -o -4 addr show | awk '!/ lo / {print $2 " " $4}' | awk '/^(tun|tap|eth|en|ens|wlan)/ {print $1; exit}' || true)
  if [ -n "$IF" ]; then echo "$IF"; return; fi
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
  read -r -p "Ingresa el prefijo IP de la /24 de la VPN (ej: 192.168.2.) [192.168.2.]: " TMP_PREFIX
  VPN_NET_PREFIX="${TMP_PREFIX:-192.168.2.}"
fi
echo "Usando interfaz ${IF_IN} y prefijo ${VPN_NET_PREFIX} (se formará ${VPN_NET_PREFIX}0/24)"

# ---------------------------
# 3) preparar dirs
# ---------------------------
mkdir -p "${HORUS_DIR}"
chown root:root "${HORUS_DIR}"
chmod 755 "${HORUS_DIR}"

mkdir -p "${LOG_DIR}"
chown root:root "${LOG_DIR}"
chmod 755 "${LOG_DIR}"

# If SELinux Enforcing, ensure semanage available and set fcontext
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
  echo "SELinux: Enforcing detected. Ajustando contexto para ${LOG_DIR}..."
  if ! command -v semanage >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then
      dnf -y install policycoreutils-python-utils || true
    elif command -v apt-get >/dev/null 2>&1; then
      apt-get install -y policycoreutils || true
    fi
  fi
  if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t var_log_t "${LOG_DIR}(/.*)?" >/dev/null 2>&1 || true
    restorecon -Rv "${LOG_DIR}" || true
  else
    echo "Warning: semanage no disponible; revisa manualmente SELinux contexts si hay problemas."
  fi
fi

# ---------------------------
# 4) crear addons y horus.py (logs en /var/log/horus)
# ---------------------------
cat > "${HORUS_DIR}/mitm_simple_logger.py" <<'PYMITM'
# mitm_simple_logger.py
from mitmproxy import http, ctx
import datetime, os
OUTFILE = "/var/log/horus/http_access.log"
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

printf 'VPN_NET_PREFIX = "%s"\n\n' "${VPN_NET_PREFIX}" > "${HORUS_DIR}/ssh_log_watcher.py"
cat >> "${HORUS_DIR}/ssh_log_watcher.py" <<'PYSSH'
# ssh_log_watcher.py
import re, subprocess, os, datetime, sys
OUTFILE = "/var/log/horus/ssh_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
open(OUTFILE, "a").close()
RE_ACCEPT = re.compile(r"Accepted .* for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_FAILED = re.compile(r"Failed .* for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
def parse_line(line):
    m = RE_ACCEPT.search(line)
    if m:
        return (m.group("ip"), "ACCEPTED", m.group("user"), line.strip())
    m2 = RE_FAILED.search(line)
    if m2:
        return (m2.group("ip"), "FAILED", m2.group("user"), line.strip())
    return None
def tail_journal():
    return ["journalctl", "-u", "sshd.service", "-f", "-o", "short"]
def tail_authlog():
    return ["tail", "-F", "/var/log/auth.log"]
def run_forever():
    use_journal = False
    try:
        subprocess.run(["journalctl","-u","sshd.service","--no-pager","-n","1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        use_journal = True
    except Exception:
        use_journal = False
    cmd = tail_journal() if use_journal else tail_authlog()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for raw in p.stdout:
            parsed = parse_line(raw)
            if not parsed:
                continue
            ip, ev, user, details = parsed
            if not ip.startswith(VPN_NET_PREFIX):
                continue
            line = f"{now()}\t{ip}\t{ev}\t{user}\t{details}\n"
            with open(OUTFILE, "a") as f:
                f.write(line)
    except KeyboardInterrupt:
        p.terminate()
        return
    except Exception:
        p.terminate()
        return
if __name__ == "__main__":
    run_forever()
PYSSH

# --- New: Flow sniffer module (TCP/UDP) ---
cat > "${HORUS_DIR}/flow_sniffer.py" <<'PYSNIFF'
#!/usr/bin/env python3
# flow_sniffer.py
# Escribe CSV: timestamp,src_ip,dst_ip,dst_port,protocol
import os, sys, csv
from datetime import datetime
try:
    from scapy.all import sniff, IP, TCP, UDP
except Exception as e:
    print("ERROR: scapy no está disponible. Instala scapy en el venv: /opt/horus/venv/bin/pip install scapy")
    sys.exit(2)

LOG_CSV = "/var/log/horus/flows.csv"
IFACE = os.environ.get("HORUS_IFACE", "tun0")

os.makedirs(os.path.dirname(LOG_CSV), exist_ok=True)
if not os.path.exists(LOG_CSV):
    with open(LOG_CSV, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp","src_ip","dst_ip","dst_port","protocol"])

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def handle_pkt(pkt):
    if not pkt.haslayer(IP):
        return
    proto = None
    dst_port = ""
    if pkt.haslayer(TCP):
        proto = "TCP"
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dst_port = pkt[UDP].dport
    else:
        return
    row = [ now_iso(), pkt[IP].src, pkt[IP].dst, str(dst_port), proto ]
    try:
        with open(LOG_CSV, "a", newline="") as f:
            csv.writer(f).writerow(row)
    except Exception:
        pass

def main():
    iface = IFACE
    if len(sys.argv) > 1 and sys.argv[1]:
        iface = sys.argv[1]
    print(f"flow_sniffer: iniciando en iface={iface}, log={LOG_CSV}")
    sniff(iface=iface, filter="ip and (tcp or udp)", prn=handle_pkt, store=False)

if __name__ == "__main__":
    main()
PYSNIFF

chmod 755 "${HORUS_DIR}/flow_sniffer.py"

# horus.py variables + body (point logs to /var/log/horus)
printf 'IF_IN = "%s"\nVPN_NET = "%s0/24"\nMITM_ADDON = "%s"\nMITM_PORT = 8080\nMITMDUMP_BIN = "%s"\nCERT_PATH = "%s"\nCERT_PATH_WIN = "%s"\nSSH_WATCHER = "%s"\nFLOW_SNIFFER = "%s"\nHTTP_LOG = "/var/log/horus/http_access.log"\nSSH_LOG = "/var/log/horus/ssh_access.log"\nFLOW_LOG = "/var/log/horus/flows.csv"\n\n' \
  "${IF_IN}" "${VPN_NET_PREFIX}" "${HORUS_DIR}/mitm_simple_logger.py" "${MITM_ENTRY}" "${CERT_PEM_DST}" "${CERT_CER_DST}" "${HORUS_DIR}/ssh_log_watcher.py" "${HORUS_DIR}/flow_sniffer.py" > "${HORUS_DIR}/horus.py"

cat >> "${HORUS_DIR}/horus.py" <<'PYHORUS_BODY'
#!/usr/bin/env python3
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
    print(banner); print(eye)
    print("Horus iniciado. Cert PEM:", CERT_PATH)
    print("Cert CER (Windows):", CERT_PATH_WIN); print()
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
def add_iptables():
    try:
        run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","80","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception:
        pass
    try:
        run_cmd(["iptables","-t","nat","-A","PREROUTING","-i",IF_IN,"-s",VPN_NET,"-p","tcp","--dport","443","-j","REDIRECT","--to-ports",str(MITM_PORT)])
    except Exception:
        pass
    try:
        run_cmd(["sysctl","-w","net.ipv4.ip_forward=1"])
    except Exception:
        pass
def rule_exists(rule):
    try:
        cmd = ["iptables","-t","nat","-C","PREROUTING"] + rule
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False
def del_iptables():
    rule1 = ["-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)]
    rule2 = ["-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)]
    try:
        if rule_exists(rule1):
            run_cmd(["iptables","-t","nat","-D","PREROUTING"] + rule1)
    except Exception as e:
        print("Error borrando regla 80:", e)
    try:
        if rule_exists(rule2):
            run_cmd(["iptables","-t","nat","-D","PREROUTING"] + rule2)
    except Exception as e:
        print("Error borrando regla 443:", e)
def start_mitmdump():
    if os.path.exists(MITMDUMP_BIN):
        return subprocess.Popen([MITMDUMP_BIN,"--mode","transparent","--listen-port",str(MITM_PORT),"-s",MITM_ADDON])
    else:
        return subprocess.Popen(["mitmdump","--mode","transparent","--listen-port",str(MITM_PORT),"-s",MITM_ADDON])
def start_ssh_watcher():
    return subprocess.Popen(["python3", SSH_WATCHER])
def start_flow_sniffer():
    # intenta usar el python del venv si existe
    vpy = os.path.join(os.path.dirname(MITMDUMP_BIN), "python")
    if os.path.exists(vpy):
        return subprocess.Popen([vpy, FLOW_SNIFFER])
    # fallback
    return subprocess.Popen(["python3", FLOW_SNIFFER])
def main():
    check_root()
    print_banner()
    print("Interfaz:", IF_IN, "VPN:", VPN_NET)
    add_iptables()
    mitm_proc = start_mitmdump()
    ssh_proc = start_ssh_watcher()
    flow_proc = start_flow_sniffer()
    def shutdown(signum, frame):
        try:
            mitm_proc.terminate()
        except Exception:
            pass
        try:
            ssh_proc.terminate()
        except Exception:
            pass
        try:
            flow_proc.terminate()
        except Exception:
            pass
        time.sleep(1)
        del_iptables()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    open(HTTP_LOG,"a").close()
    open(SSH_LOG,"a").close()
    open(FLOW_LOG,"a").close()
    try:
        while True:
            if mitm_proc.poll() is not None:
                print("mitmdump terminó con código", mitm_proc.returncode)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown(None, None)
if __name__ == "__main__":
    main()
PYHORUS_BODY

chmod 644 "${HORUS_DIR}/mitm_simple_logger.py" "${HORUS_DIR}/ssh_log_watcher.py" "${HORUS_DIR}/flow_sniffer.py"

# asegurar shebang y limpiar CRLF en horus.py
if ! head -n1 "${HORUS_DIR}/horus.py" | grep -q '^#!'; then
  sed -i '1i #!/usr/bin/env python3' "${HORUS_DIR}/horus.py"
fi
if command -v dos2unix >/dev/null 2>&1; then
  dos2unix "${HORUS_DIR}/horus.py" || true
else
  awk '{ sub(/\r$/,""); print }' "${HORUS_DIR}/horus.py" > "${HORUS_DIR}/.horus.tmp" && mv "${HORUS_DIR}/.horus.tmp" "${HORUS_DIR}/horus.py"
fi
chmod 755 "${HORUS_DIR}/horus.py"

# ---------------------------
# 5) crear venv e instalar mitmproxy + scapy
# ---------------------------
echo "==> Creando venv en ${VENV_DIR} e instalando mitmproxy (puede tardar)..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
"${VENV_DIR}/bin/pip" install mitmproxy scapy >/dev/null || true

# ---------------------------
# 6) OPCIÓN CA: intentar mitmproxy bootstrap, si falla usar OPENSSL fallback
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
  export HOME=/root
  export LANG=en_US.UTF-8
  export LC_ALL=en_US.UTF-8
  rm -f "${BOOTLOG}" || true

  # Ejecuta mitmproxy headless con confdir explícito; espera la aparición del cert
  if [ -x "${MITM_ENTRY}" ]; then
    "${MITM_ENTRY}" --set confdir="${MITM_CONF_DIR}" --listen-port 0 -s /dev/null -q > "${BOOTLOG}" 2>&1 &
    MPID=$!
  else
    "${MITMPROXY_PY}" -m mitmproxy.tools.dump --set confdir="${MITM_CONF_DIR}" --listen-port 0 -s /dev/null -q > "${BOOTLOG}" 2>&1 &
    MPID=$!
  fi

  # Esperar hasta 8s por el PEM (comprueba cada 1s)
  for i in {1..8}; do
    sleep 1
    if [ -f "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" ]; then break; fi
  done

  # terminar proceso de bootstrap si sigue vivo
  kill ${MPID} >/dev/null 2>&1 || true
  wait ${MPID} 2>/dev/null || true

  if [ -f "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" ]; then
    echo "==> CA generada por mitmproxy. Copiando a ${CERT_PEM_DST}..."
    cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"
    chmod 644 "${CERT_PEM_DST}"
    if command -v openssl >/dev/null 2>&1; then
      openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
      chmod 644 "${CERT_CER_DST}" || true
    fi
    echo "==> CA lista."
  else
    echo "WARNING: mitmproxy no generó la CA en el bootstrap. Aplicando fallback OpenSSL..."
    # Fallback: generar CA con OpenSSL y colocar en confdir para que mitmproxy la use
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
    cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"
    chmod 644 "${CERT_PEM_DST}"
    if command -v openssl >/dev/null 2>&1; then
      openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
      chmod 644 "${CERT_CER_DST}" || true
    fi
    set +eux
    echo "==> Fallback OpenSSL completado: CA creada y copiada a ${CERT_PEM_DST}"
  fi

else
  echo "==> Opción: usar CA + KEY provistos por el usuario"
  read -r -p "Ruta al CERT PEM (cert de CA o archivo combinado key+cert) [/root/my-ca.pem]: " USER_CERT
  USER_CERT="${USER_CERT:-/root/my-ca.pem}"
  read -r -p "Si el CERT no contiene la KEY, ruta a la KEY [/root/my-ca.key] (vacío si el CERT ya incluye la KEY): " USER_KEY
  USER_KEY="${USER_KEY:-}"

  if [ ! -f "${USER_CERT}" ]; then echo "ERROR: no existe ${USER_CERT}"; exit 1; fi
  if [ -n "${USER_KEY}" ] && [ ! -f "${USER_KEY}" ]; then echo "ERROR: no existe ${USER_KEY}"; exit 1; fi

  # Validar que sea CA
  if ! openssl x509 -in "${USER_CERT}" -noout -text >/tmp/_horus_cert.txt 2>/dev/null; then
    echo "ERROR: no se pudo leer ${USER_CERT} con openssl"; exit 1
  fi
  if ! grep -q "CA:TRUE" /tmp/_horus_cert.txt; then
    echo "ERROR: el certificado NO es de CA (falta basicConstraints: CA:TRUE)."
    echo "Un wildcard o cert de servidor NO sirve. Usa la opción automática o provee una CA real."
    exit 1
  fi
  if awk '/Key Usage/{flag=1;next}/^[[:alpha:]-]+:/{flag=0}flag' /tmp/_horus_cert.txt | grep -qi "keyCertSign"; then
    echo "Key Usage incluye keyCertSign (ok)"
  else
    echo "ADVERTENCIA: la CA no declara keyCertSign; algunos clientes podrían rechazarla."
  fi

  mkdir -p "${MITM_CONF_DIR}"
  if grep -q "PRIVATE KEY" "${USER_CERT}" 2>/dev/null; then
    cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    awk '/-----BEGIN CERTIFICATE-----/{flag=1}flag{print}/-----END CERTIFICATE-----/{exit}' "${USER_CERT}" > "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" \
      || cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
  else
    if [ -z "${USER_KEY}" ]; then echo "ERROR: certificado sin clave privada."; exit 1; fi
    cat "${USER_KEY}" "${USER_CERT}" > "${MITM_CONF_DIR}/mitmproxy-ca.pem"
    cp "${USER_CERT}" "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem"
  fi
  chmod 600 "${MITM_CONF_DIR}/mitmproxy-ca.pem" || true
  chmod 644 "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" || true
  cp "${MITM_CONF_DIR}/mitmproxy-ca-cert.pem" "${CERT_PEM_DST}"
  chmod 644 "${CERT_PEM_DST}"
  if command -v openssl >/dev/null 2>&1; then
    openssl x509 -outform der -in "${CERT_PEM_DST}" -out "${CERT_CER_DST}" || true
    chmod 644 "${CERT_CER_DST}" || true
  fi
  echo "==> Usando CA provista. Cert copiado a: ${CERT_PEM_DST}"
fi

# ---------------------------
# 7) crear systemd unit y arrancar servicio
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
# 8) wrapper + PATH + symlink
# ---------------------------
cat > "${WRAPPER}" <<'WRAP'
#!/usr/bin/env bash
HORUS_SERVICE="horus"
HORUS_DIR="/opt/horus"
CERT_PEM="${HORUS_DIR}/mitmproxy-ca-cert.pem"
CERT_CER="${HORUS_DIR}/mitmproxy-ca-cert.cer"
print_help() {
  cat <<'HHELP'
horus — wrapper para el servicio Horus

Uso:
  horus start       Inicia el servicio
  horus stop        Detiene el servicio
  horus restart     Reinicia el servicio y muestra status
  horus status      Muestra estado del servicio
  horus logs        Muestra últimos 200 líneas de http + ssh logs
  horus flows       Muestra últimos 200 líneas del CSV de flows
  horus certpath    Imprime la ruta del certificado a distribuir
  horus install-cert /ruta/al/mitmproxy-ca-cert.cer  Copia un .cer al directorio Horus
  horus uninstall   Elimina Horus completamente (scripts, logs, certs)
  horus help|-h     Esta ayuda
HHELP
}
case "${1:-help}" in
  start) systemctl start ${HORUS_SERVICE}; systemctl status ${HORUS_SERVICE} --no-pager ;;
  stop) systemctl stop ${HORUS_SERVICE} ;;
  restart) systemctl restart ${HORUS_SERVICE}; systemctl status ${HORUS_SERVICE} --no-pager ;;
  status) systemctl status ${HORUS_SERVICE} --no-pager ;;
  logs) tail -n 200 "${HORUS_DIR}/http_access.log" 2>/dev/null || true; echo "----"; tail -n 200 "${HORUS_DIR}/ssh_access.log" 2>/dev/null || true ;;
  flows) tail -n 200 "${HORUS_DIR}/flows.csv" 2>/dev/null || true ;;
  certpath) echo "${CERT_PEM}" ;;
  install-cert)
    if [ -z "${2:-}" ]; then echo "Uso: horus install-cert /ruta/al/mitmproxy-ca-cert.cer"; exit 2; fi
    cp "$2" "${CERT_CER}" || { echo "Error copiando"; exit 1; }
    echo "Cert copiado a ${CERT_CER}"
    ;;
  uninstall)
    echo "Deteniendo servicio..."
    systemctl stop horus.service || true
    systemctl disable horus.service || true
    rm -f /etc/systemd/system/horus.service
    echo "Borrando archivos..."
    rm -rf /opt/horus /var/log/horus /root/.mitmproxy
    rm -f /usr/local/bin/horus /usr/bin/horus
    systemctl daemon-reload
    echo "Horus desinstalado."
    ;;
  help|--help|-h|*) print_help ;;
esac
WRAP

chmod 755 "${WRAPPER}"
ln -sf "${WRAPPER}" /usr/bin/horus || true
if ! echo "$PATH" | tr ':' '\n' | grep -q '^/usr/local/bin$'; then
  echo 'export PATH="/usr/local/bin:$PATH"' > /etc/profile.d/horus_path.sh
  chmod 644 /etc/profile.d/horus_path.sh
fi

# ---------------------------
# 9) asegurar shebang/CRLF en horus.py (último paso)
# ---------------------------
if ! head -n1 "${HORUS_DIR}/horus.py" | grep -q '^#!'; then
  sed -i '1i #!/usr/bin/env python3' "${HORUS_DIR}/horus.py"
fi
if command -v dos2unix >/dev/null 2>&1; then
  dos2unix "${HORUS_DIR}/horus.py" || true
else
  awk '{ sub(/\r$/,""); print }' "${HORUS_DIR}/horus.py" > "${HORUS_DIR}/.horus.tmp" && mv "${HORUS_DIR}/.horus.tmp" "${HORUS_DIR}/horus.py"
fi
chmod 755 "${HORUS_DIR}/horus.py"

# ---------------------------
# 10) finalizar y presentar info
# ---------------------------
echo
echo "==== Instalación completada ===="
echo " - Horus instalado en: ${HORUS_DIR}"
echo " - Servicio systemd: horus.service"
echo " - Wrapper: ${WRAPPER} (usa 'horus -h') y symlink /usr/bin/horus"
echo " - Logs: ${LOG_DIR}/http_access.log, ${LOG_DIR}/ssh_access.log, ${LOG_DIR}/flows.csv"
echo " - Cert PEM para distribuir: ${CERT_PEM_DST}"
echo " - Cert CER (Windows DER) para distribuir: ${CERT_CER_DST}"
echo
echo "Instala el CERT (CER) en los clientes VPN como Trust Root CA (Windows/macOS/Linux/Firefox) y reinicia el navegador."
echo
systemctl status horus --no-pager -l || true
journalctl -u horus -n 80 --no-pager -l || true
