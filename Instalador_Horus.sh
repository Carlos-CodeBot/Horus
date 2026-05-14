#!/usr/bin/env bash
# Instalador_Horus.sh
# Ejecutar como root.
# Herramienta desarrollada por H4cker.
# Modulo de alta carga

set -euo pipefail
IFS=$'\n\t'

HORUS_DIR="/opt/horus"
VENV_DIR="${HORUS_DIR}/venv"
MITM_ENTRY="${VENV_DIR}/bin/mitmdump"
MITMPROXY_PY="${VENV_DIR}/bin/python"
HORUS_SERVICE="/etc/systemd/system/horus.service"
CERT_PEM_DST="${HORUS_DIR}/mitmproxy-ca-cert.pem"
CERT_CER_DST="${HORUS_DIR}/mitmproxy-ca-cert.cer"
WILDCARD_PEM_DST="${HORUS_DIR}/mitmproxy-wildcard.pem"
WRAPPER="/usr/local/bin/horus"
WRAPPER_PURGE="/usr/local/bin/horus-uninstall"
MITM_CONF_DIR="/root/.mitmproxy"
BOOTLOG="/root/mitmproxy_bootstrap.log"
LOG_DIR="/var/log/horus"
EXCEPTIONS_FILE="${HORUS_DIR}/exceptions.txt"

echo "==== Instalador Horus (full, logs en ${LOG_DIR}) ===="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script necesita permisos de root. Ejecuta con sudo."
  exit 1
fi

echo "Aviso: Asegurate de tener autorizacion para interceptar TLS en las maquinas objetivo."

# ---------------------------
# 1) Dependencias
# ---------------------------
if command -v dnf >/dev/null 2>&1; then
  echo "==> Instalando dependencias con dnf..."
  dnf -y install python3 python3-virtualenv python3-pip python3-devel gcc \
                 openssl-devel libffi-devel redhat-rpm-config iptables iproute \
                 dos2unix glibc-langpack-en policycoreutils-python-utils git || true
elif command -v apt-get >/dev/null 2>&1; then
  echo "==> Instalando dependencias con apt..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip python3-dev gcc \
                                                  libssl-dev libffi-dev iptables iproute2 dos2unix policycoreutils git || true
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
  read -r -p "No se detecto interfaz tun/tap automaticamente. Ingresa la interfaz a usar [tun0]: " IF_IN
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

echo "Usando interfaz ${IF_IN} y prefijo ${VPN_NET_PREFIX} (se formara ${VPN_NET_PREFIX}0/24)"

# ---------------------------
# 3) Preparar dirs + SELinux
# ---------------------------
mkdir -p "${HORUS_DIR}" "${LOG_DIR}"
chown -R root:root "${HORUS_DIR}" "${LOG_DIR}"
chmod 755 "${HORUS_DIR}" "${LOG_DIR}"
touch "${EXCEPTIONS_FILE}" && chmod 600 "${EXCEPTIONS_FILE}"

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
# 4) Addons y modulos
# ---------------------------
cat > "${HORUS_DIR}/mitm_simple_logger.py" <<'PYMITM'
from mitmproxy import http, ctx
import datetime
import os

OUTFILE = "/var/log/horus/http_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

class SimpleLogger:
    def __init__(self):
        ctx.log.info(f"mitm_simple_logger logging to {OUTFILE}")
        self._fh = open(OUTFILE, "a", buffering=1)

    def response(self, flow: http.HTTPFlow):
        try:
            fecha = now()
            ip_cliente = (
                flow.client_conn.address[0]
                if flow.client_conn and getattr(flow.client_conn, "address", None)
                else "-"
            )
            metodo = flow.request.method or "-"
            host_destino = (
                flow.request.host
                or flow.request.pretty_host
                or flow.request.headers.get("Host", "-")
                or "-"
            )
            puerto_destino = flow.request.port or "-"
            ip_destino = "-"
            try:
                if flow.server_conn and getattr(flow.server_conn, "address", None):
                    ip_destino = flow.server_conn.address[0]
            except Exception:
                ip_destino = "-"
            ruta = flow.request.path or "-"
            url = flow.request.pretty_url if getattr(flow.request, "pretty_url", None) else ruta
            codigo = flow.response.status_code if flow.response else "-"
            self._fh.write(
                f"{fecha}\t{ip_cliente}\t{host_destino}\t{ip_destino}\t{puerto_destino}\t{metodo}\t{ruta}\t{url}\t{codigo}\n"
            )
        except Exception as e:
            ctx.log.error(f"mitm_simple_logger error: {e}")

addons = [SimpleLogger()]
PYMITM

cat > "${HORUS_DIR}/mitm_wazuh_logger.py" <<'PYWAZUH'
from mitmproxy import http, ctx
import datetime
import hashlib
import json
import os

OUTFILE = "/var/log/horus/http_wazuh.json"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def safe_value(value, default="-"):
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default

def classify_status(status_code):
    try:
        code = int(status_code)
    except Exception:
        return "unknown"
    if 200 <= code <= 299:
        return "success"
    if 300 <= code <= 399:
        return "redirect"
    if 400 <= code <= 499:
        return "client_error"
    if 500 <= code <= 599:
        return "server_error"
    return "unknown"

def classify_risk(method, path, status_code):
    method = safe_value(method).upper()
    path = safe_value(path, "").lower()
    suspicious_keywords = [
        "admin", "login", "wp-admin", "phpmyadmin", ".env", "config", "backup",
        "passwd", "shadow", "shell", "cmd", "select", "union", "../", "%2e%2e",
        "base64", "eval", "script", "onerror"
    ]
    try:
        code = int(status_code)
    except Exception:
        code = 0
    if any(keyword in path for keyword in suspicious_keywords):
        return "suspicious"
    if method in ["PUT", "DELETE", "PATCH"]:
        return "interesting_method"
    if code in [401, 403]:
        return "auth_or_forbidden"
    if code == 404:
        return "not_found"
    if code >= 500:
        return "server_error"
    return "normal"

class WazuhHTTPLogger:
    def __init__(self):
        ctx.log.info(f"mitm_wazuh_logger logging to {OUTFILE}")
        self._fh = open(OUTFILE, "a", buffering=1)

    def response(self, flow: http.HTTPFlow):
        try:
            timestamp = now_iso()
            src_ip = "-"
            src_port = "-"
            if flow.client_conn and getattr(flow.client_conn, "address", None):
                src_ip = safe_value(flow.client_conn.address[0])
                if len(flow.client_conn.address) > 1:
                    src_port = flow.client_conn.address[1]

            dest_ip = "-"
            dest_port = "-"
            if flow.server_conn and getattr(flow.server_conn, "address", None):
                dest_ip = safe_value(flow.server_conn.address[0])
                if len(flow.server_conn.address) > 1:
                    dest_port = flow.server_conn.address[1]

            method = safe_value(flow.request.method)
            host_destino = safe_value(
                flow.request.host
                or flow.request.pretty_host
                or flow.request.headers.get("Host", "-")
            )
            request_port = flow.request.port or dest_port
            scheme = safe_value(flow.request.scheme)
            path = safe_value(flow.request.path)
            url = safe_value(flow.request.pretty_url if getattr(flow.request, "pretty_url", None) else path)
            status_code = flow.response.status_code if flow.response else "-"
            status_category = classify_status(status_code)
            risk = classify_risk(method, path, status_code)
            user_agent = safe_value(flow.request.headers.get("User-Agent", "-"))
            content_type = "-"
            response_size = 0
            if flow.response:
                content_type = safe_value(flow.response.headers.get("Content-Type", "-"))
                try:
                    response_size = len(flow.response.raw_content or b"")
                except Exception:
                    response_size = 0

            request_id_raw = f"{timestamp}|{src_ip}|{host_destino}|{method}|{path}|{status_code}"
            event_id = hashlib.sha256(request_id_raw.encode()).hexdigest()[:16]
            event = {
                "timestamp": timestamp,
                "event": {
                    "module": "horus",
                    "dataset": "horus.http",
                    "kind": "event",
                    "category": "web",
                    "type": "access",
                    "id": event_id,
                    "outcome": status_category,
                    "risk": risk
                },
                "source": {"ip": src_ip, "port": src_port},
                "destination": {"ip": dest_ip, "port": request_port, "domain": host_destino},
                "http": {
                    "request": {"method": method},
                    "response": {
                        "status_code": status_code,
                        "body": {"bytes": response_size},
                        "mime_type": content_type
                    }
                },
                "url": {"scheme": scheme, "domain": host_destino, "path": path, "full": url},
                "user_agent": {"original": user_agent},
                "horus": {"log_type": "http_access", "sensor": "horus-mitm"}
            }
            self._fh.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        except Exception as e:
            ctx.log.error(f"mitm_wazuh_logger error: {e}")

addons = [WazuhHTTPLogger()]
PYWAZUH

printf 'VPN_NET_PREFIX = "%s"\n\n' "${VPN_NET_PREFIX}" > "${HORUS_DIR}/ssh_log_watcher.py"
cat >> "${HORUS_DIR}/ssh_log_watcher.py" <<'PYSSH'
import re, subprocess, os, datetime
OUTFILE = "/var/log/horus/ssh_access.log"
os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
LOGFH = open(OUTFILE, "a", buffering=1)
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
            LOGFH.write(f"{now()}\t{ip}\t{ev}\t{user}\t{line.strip()}\n")
    except KeyboardInterrupt:
        p.terminate()
if __name__ == "__main__": run()
PYSSH

# ---------------------------
# 5) venv + paquetes
# ---------------------------
echo "==> Creando venv en ${VENV_DIR} e instalando mitmproxy (puede tardar)..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null
"${VENV_DIR}/bin/pip" install mitmproxy >/dev/null || true

# ---------------------------
# 6) CA: mitmproxy bootstrap -> fallback OpenSSL
# ---------------------------
echo
echo "===== OPCION CA ====="
echo "1) Generar CA automaticamente (recomendado)"
echo "2) Usar CA + KEY existentes (tu entregas rutas absolutas)"
echo "3) Usar certificado wildcard existente (*.dominio)"
read -r -p "Selecciona 1, 2 o 3 [1]: " CA_CHOICE
CA_CHOICE="${CA_CHOICE:-1}"

mkdir -p "${MITM_CONF_DIR}"
MITM_CERT_ARG=""
rm -f "${WILDCARD_PEM_DST}" || true
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
    echo "WARNING: mitmproxy no genero CA. Usando fallback OpenSSL..."
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
elif [ "${CA_CHOICE}" = "2" ]; then
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
else
  echo "==> Usar certificado wildcard (*.dominio)"
  read -r -p "Dominio wildcard (ej: *.example.com): " WILDCARD_DOMAIN
  if [ -z "${WILDCARD_DOMAIN}" ]; then
    echo "ERROR: dominio wildcard requerido"; exit 1
  fi
  read -r -p "Ruta CERT (PEM) [/root/wildcard.crt]: " WILDCARD_CERT
  WILDCARD_CERT="${WILDCARD_CERT:-/root/wildcard.crt}"
  read -r -p "Ruta FULLCHAIN (PEM) [igual a CERT]: " WILDCARD_CHAIN
  WILDCARD_CHAIN="${WILDCARD_CHAIN:-${WILDCARD_CERT}}"
  read -r -p "Ruta KEY  (PEM) [/root/wildcard.key]: " WILDCARD_KEY
  WILDCARD_KEY="${WILDCARD_KEY:-/root/wildcard.key}"
  [ -f "${WILDCARD_CERT}" ] || { echo "ERROR: no existe ${WILDCARD_CERT}"; exit 1; }
  [ -f "${WILDCARD_CHAIN}" ] || { echo "ERROR: no existe ${WILDCARD_CHAIN}"; exit 1; }
  [ -f "${WILDCARD_KEY}" ] || { echo "ERROR: no existe ${WILDCARD_KEY}"; exit 1; }
  if ! openssl x509 -in "${WILDCARD_CERT}" -noout >/dev/null 2>&1; then
    echo "ERROR: certificado invalido"; exit 1
  fi
  if ! openssl rsa -in "${WILDCARD_KEY}" -check -noout >/dev/null 2>&1 && ! openssl pkey -in "${WILDCARD_KEY}" -text -noout >/dev/null 2>&1; then
    echo "ERROR: llave privada invalida"; exit 1
  fi
  CERT_MOD=$(openssl x509 -noout -modulus -in "${WILDCARD_CERT}" 2>/dev/null | openssl md5 | awk '{print $2}')
  KEY_MOD=$(openssl rsa -noout -modulus -in "${WILDCARD_KEY}" 2>/dev/null | openssl md5 | awk '{print $2}')
  [ -n "${CERT_MOD}" ] && [ -n "${KEY_MOD}" ] && [ "${CERT_MOD}" = "${KEY_MOD}" ] || {
    echo "ERROR: la llave privada no corresponde al certificado wildcard"; exit 1
  }
  cat "${WILDCARD_KEY}" "${WILDCARD_CHAIN}" > "${WILDCARD_PEM_DST}"
  chmod 600 "${WILDCARD_PEM_DST}" || true
  MITM_CERT_ARG="*=${WILDCARD_PEM_DST}"
  cp "${WILDCARD_CERT}" "${CERT_PEM_DST}" && chmod 644 "${CERT_PEM_DST}" || true
  command -v openssl >/dev/null 2>&1 && openssl x509 -outform der -in "${WILDCARD_CERT}" -out "${CERT_CER_DST}" || true
  chmod 644 "${CERT_CER_DST}" || true
fi

# ---------------------------
# 7) horus.py (arranca mitm + ssh watcher)
# ---------------------------
printf 'IF_IN = "%s"\nVPN_NET = "%s0/24"\nMITM_ADDON = "%s"\nWAZUH_ADDON = "%s"\nMITM_PORT = 8080\nMITMDUMP_BIN = "%s"\nCERT_PATH = "%s"\nCERT_PATH_WIN = "%s"\nMITM_CERT = "%s"\nSSH_WATCHER = "%s"\nHTTP_LOG = "%s/http_access.log"\nWAZUH_LOG = "%s/http_wazuh.json"\nSSH_LOG = "%s/ssh_access.log"\nEXCEPTIONS_FILE = "%s"\n\n' \
  "${IF_IN}" "${VPN_NET_PREFIX}" "${HORUS_DIR}/mitm_simple_logger.py" "${HORUS_DIR}/mitm_wazuh_logger.py" "${MITM_ENTRY}" "${CERT_PEM_DST}" "${CERT_CER_DST}" "${MITM_CERT_ARG}" "${HORUS_DIR}/ssh_log_watcher.py" "${LOG_DIR}" "${LOG_DIR}" "${LOG_DIR}" "${EXCEPTIONS_FILE}" > "${HORUS_DIR}/horus.py"

cat >> "${HORUS_DIR}/horus.py" <<'PYHORUS'
#!/usr/bin/env python3
import subprocess, signal, time, os, sys
from typing import List

def print_banner():
    print(r"""
  _   _   ____   _   _   ____   _____
 | | | | / ___| | | | | / ___| | ____|
 | | | || |  _  | | | | \___ \ |  _|
 | |_| || |_| | | |_| |  ___) || |___
  \___/  \____|  \___/  |____/ |_____|
""")
    print("Horus iniciado. Cert PEM:", CERT_PATH)
    print("Cert CER (Windows):", CERT_PATH_WIN)
    print("Log HTTP:", HTTP_LOG)
    print("Log Wazuh JSON:", WAZUH_LOG)
    if MITM_CERT:
        print("Cert wildcard cargado:", MITM_CERT)
    print()

def check_root():
    if os.geteuid() != 0:
        print("Horus necesita ejecutarse como root.")
        sys.exit(1)

def run_cmd(cmd):
    try:
        return subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print("Comando fallo:", e)
        return e.returncode

def load_exceptions() -> List[str]:
    if not EXCEPTIONS_FILE or not os.path.exists(EXCEPTIONS_FILE):
        return []
    try:
        with open(EXCEPTIONS_FILE, "r") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except Exception:
        return []

def rule_exists(rule):
    try:
        subprocess.check_call(["iptables", "-t", "nat", "-C", "PREROUTING"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def add_iptables():
    for ip in load_exceptions():
        for port in ("80", "443"):
            rule = ["-i", IF_IN, "-s", VPN_NET, "-d", ip, "-p", "tcp", "--dport", port, "-j", "RETURN"]
            try:
                if not rule_exists(rule):
                    run_cmd(["iptables", "-t", "nat", "-I", "PREROUTING"] + rule)
            except Exception:
                pass
    try:
        run_cmd(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)])
    except Exception:
        pass
    try:
        run_cmd(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", str(MITM_PORT)])
    except Exception:
        pass
    try:
        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    except Exception:
        pass

def del_iptables():
    for ip in load_exceptions():
        for port in ("80", "443"):
            r = ["-i", IF_IN, "-s", VPN_NET, "-d", ip, "-p", "tcp", "--dport", port, "-j", "RETURN"]
            try:
                if rule_exists(r):
                    run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING"] + r)
            except Exception as e:
                print("Error borrando bypass", ip, port, e)
    for port in ("80", "443"):
        r = ["-i", IF_IN, "-s", VPN_NET, "-p", "tcp", "--dport", port, "-j", "REDIRECT", "--to-ports", str(MITM_PORT)]
        try:
            if rule_exists(r):
                run_cmd(["iptables", "-t", "nat", "-D", "PREROUTING"] + r)
        except Exception as e:
            print("Error borrando regla", port, e)

def build_mitmdump_cmd(bin_path):
    cmd = [bin_path, "--mode", "transparent", "--listen-port", str(MITM_PORT), "--set", "http2=false"]
    if MITM_CERT:
        cmd.extend(["--certs", MITM_CERT])
    cmd.extend(["-s", MITM_ADDON])
    cmd.extend(["-s", WAZUH_ADDON])
    return cmd

def start_mitmdump():
    if os.path.exists(MITMDUMP_BIN):
        return subprocess.Popen(build_mitmdump_cmd(MITMDUMP_BIN))
    return subprocess.Popen(build_mitmdump_cmd("mitmdump"))

def start_py(mod):
    vpy = os.path.join(os.path.dirname(MITMDUMP_BIN), "python")
    if os.path.exists(vpy):
        return subprocess.Popen([vpy, mod])
    return subprocess.Popen(["python3", mod])

def main():
    check_root()
    print_banner()
    print("Interfaz:", IF_IN, "VPN:", VPN_NET)
    for p in (HTTP_LOG, WAZUH_LOG, SSH_LOG):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "a").close()
    add_iptables()
    procs = [start_mitmdump(), start_py(SSH_WATCHER)]
    def shutdown(*_):
        for pr in procs:
            try:
                pr.terminate()
            except Exception:
                pass
        time.sleep(1)
        del_iptables()
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    try:
        while True:
            dead = [p for p in procs if p.poll() is not None]
            if dead:
                print("Subproceso termino, cerrando Horus.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()

if __name__ == "__main__":
    main()
PYHORUS

if ! head -n1 "${HORUS_DIR}/horus.py" | grep -q '^#!'; then
  sed -i '1i #!/usr/bin/env python3' "${HORUS_DIR}/horus.py"
fi
command -v dos2unix >/dev/null 2>&1 && dos2unix "${HORUS_DIR}/horus.py" || true
chmod 755 "${HORUS_DIR}/horus.py"
chmod 644 "${HORUS_DIR}/mitm_simple_logger.py" "${HORUS_DIR}/mitm_wazuh_logger.py" "${HORUS_DIR}/ssh_log_watcher.py"

# ---------------------------
# 8) systemd unit y arranque
# ---------------------------
cat > "${HORUS_SERVICE}" <<'EOF'
[Unit]
Description=Horus - simple VPN HTTP+SSH tracer (mitm + ssh watcher)
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
# 9) Wrapper
# ---------------------------
cat > /usr/local/bin/horus <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail

HORUS_SERVICE="horus.service"
HORUS_DIR="/opt/horus"
LOG_DIR="/var/log/horus"
CERT_PEM="${HORUS_DIR}/mitmproxy-ca-cert.pem"
CERT_CER="${HORUS_DIR}/mitmproxy-ca-cert.cer"
EXCEPTIONS_FILE="${HORUS_DIR}/exceptions.txt"

print_help() {
  cat <<'HHELP'
horus — wrapper para el servicio Horus

Uso:
  horus start         Inicia el servicio
  horus stop          Detiene el servicio
  horus restart       Reinicia el servicio y muestra status
  horus status        Muestra estado del servicio
  horus logs          Muestra ultimos eventos HTTP, Wazuh JSON y SSH
  horus certpath      Muestra rutas de certificados
  horus excepcion add <IP>     Anade una IP a excepciones
  horus excepcion remove <IP>  Quita una IP de excepciones
  horus excepcion list         Lista IPs exceptuadas
  horus actualizar    Actualiza Horus desde /etc/horus.env
  horus install-cert /ruta/al/mitmproxy-ca-cert.cer
  horus uninstall     Desinstala COMPLETAMENTE Horus
  horus help|-h       Esta ayuda
HHELP
}

valid_ip() { printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
ensure_exceptions_file() { [ -f "${EXCEPTIONS_FILE}" ] || { touch "${EXCEPTIONS_FILE}" && chmod 600 "${EXCEPTIONS_FILE}"; }; }

load_update_env() {
  if [ -f /etc/horus.env ]; then
    . /etc/horus.env
  fi
  HORUS_UPDATE_REPO="${HORUS_UPDATE_REPO:-}"
  HORUS_UPDATE_REF="${HORUS_UPDATE_REF:-main}"
}

load_horus_vars() {
  IF_IN=$(python3 - <<'PY'
import re
c=open("/opt/horus/horus.py").read()
m=re.search(r'IF_IN\s*=\s*"([^"]+)"', c)
print(m.group(1) if m else "tun0")
PY
)
  VPN_NET=$(python3 - <<'PY'
import re
c=open("/opt/horus/horus.py").read()
m=re.search(r'VPN_NET\s*=\s*"([^"]+)"', c)
print(m.group(1) if m else "10.38.0.0/24")
PY
)
  MITM_PORT=$(python3 - <<'PY'
import re
c=open("/opt/horus/horus.py").read()
m=re.search(r'MITM_PORT\s*=\s*(\d+)', c)
print(m.group(1) if m else "8080")
PY
)
}

rule_exists() { iptables -t nat -C PREROUTING "$@" >/dev/null 2>&1; }

add_bypass_rules() {
  local ip="$1"
  load_horus_vars
  ensure_exceptions_file
  for port in 80 443; do
    if ! rule_exists -i "$IF_IN" -s "$VPN_NET" -d "$ip" -p tcp --dport "$port" -j RETURN; then
      iptables -t nat -I PREROUTING -i "$IF_IN" -s "$VPN_NET" -d "$ip" -p tcp --dport "$port" -j RETURN || true
    fi
  done
}

del_bypass_rules() {
  local ip="$1"
  load_horus_vars
  ensure_exceptions_file
  for port in 80 443; do
    rule_exists -i "$IF_IN" -s "$VPN_NET" -d "$ip" -p tcp --dport "$port" -j RETURN \
      && iptables -t nat -D PREROUTING -i "$IF_IN" -s "$VPN_NET" -d "$ip" -p tcp --dport "$port" -j RETURN || true
  done
}

purge_iptables() {
  load_horus_vars
  if [ -f "${EXCEPTIONS_FILE}" ]; then
    while IFS= read -r ip; do
      [ -z "$ip" ] && continue
      case "$ip" in \#*) continue ;; esac
      del_bypass_rules "$ip"
    done < "${EXCEPTIONS_FILE}"
  fi
  for port in 80 443; do
    iptables -t nat -C PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport "$port" -j REDIRECT --to-ports "$MITM_PORT" >/dev/null 2>&1 \
      && iptables -t nat -D PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport "$port" -j REDIRECT --to-ports "$MITM_PORT" || true
  done
}

do_uninstall() {
  echo "[*] Deteniendo servicio..."
  systemctl stop "${HORUS_SERVICE}" || true
  systemctl disable "${HORUS_SERVICE}" || true
  echo "[*] Matando procesos residuales..."
  pkill -f "/opt/horus/venv/bin/mitmdump" 2>/dev/null || true
  pkill -f "/opt/horus/ssh_log_watcher.py" 2>/dev/null || true
  pkill -f "/opt/horus/horus.py" 2>/dev/null || true
  echo "[*] Quitando reglas NAT..."
  purge_iptables
  echo "[*] Eliminando unit y recargando systemd..."
  rm -f /etc/systemd/system/horus.service
  systemctl daemon-reload
  echo "[*] Eliminando archivos y logs..."
  rm -rf /opt/horus /var/log/horus /root/.mitmproxy
  rm -f /usr/local/bin/horus /usr/bin/horus /usr/local/bin/horus-uninstall /etc/profile.d/horus_path.sh
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    command -v semanage >/dev/null 2>&1 && semanage fcontext -d '/var/log/horus(/.*)?' 2>/dev/null || true
    restorecon -Rv /var/log >/dev/null 2>&1 || true
  fi
  echo "Horus desinstalado COMPLETAMENTE."
}

update_horus() {
  load_update_env
  if [ -z "${HORUS_UPDATE_REPO}" ]; then
    echo "Configura HORUS_UPDATE_REPO en /etc/horus.env para usar 'horus actualizar'."
    return 2
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "Este comando necesita permisos de root."
    return 1
  fi
  local tmpdir backup_exc
  tmpdir=$(mktemp -d)
  backup_exc=$(mktemp)
  [ -f "${EXCEPTIONS_FILE}" ] && cp "${EXCEPTIONS_FILE}" "${backup_exc}"
  echo "[*] Actualizando desde ${HORUS_UPDATE_REPO} (${HORUS_UPDATE_REF})..."
  git clone --depth 1 --branch "${HORUS_UPDATE_REF}" "${HORUS_UPDATE_REPO}" "${tmpdir}/horus" >/dev/null 2>&1 || {
    echo "ERROR: no se pudo clonar el repositorio."
    rm -rf "${tmpdir}" "${backup_exc}"
    return 1
  }
  bash "${tmpdir}/horus/Instalador_Horus.sh"
  if [ -s "${backup_exc}" ]; then
    cp "${backup_exc}" "${EXCEPTIONS_FILE}"
    chmod 600 "${EXCEPTIONS_FILE}"
  fi
  rm -rf "${tmpdir}" "${backup_exc}"
  echo "[*] Actualizacion completada."
}

case "${1:-help}" in
  start)
    purge_iptables
    systemctl start ${HORUS_SERVICE}
    systemctl status ${HORUS_SERVICE} --no-pager
    ;;
  stop)
    systemctl stop ${HORUS_SERVICE} || true
    purge_iptables
    ;;
  restart)
    systemctl stop ${HORUS_SERVICE} || true
    purge_iptables
    systemctl start ${HORUS_SERVICE}
    systemctl status ${HORUS_SERVICE} --no-pager
    ;;
  status) systemctl status ${HORUS_SERVICE} --no-pager ;;
  logs)
    echo "=== HTTP ==="; tail -n 200 "${LOG_DIR}/http_access.log" 2>/dev/null || echo "No hay http_access.log"
    echo "=== WAZUH JSON ==="; tail -n 50 "${LOG_DIR}/http_wazuh.json" 2>/dev/null || echo "No hay http_wazuh.json"
    echo "=== SSH ==="; tail -n 200 "${LOG_DIR}/ssh_access.log" 2>/dev/null || echo "No hay ssh_access.log"
    ;;
  certpath)
    echo "Windows (CER/DER): ${CERT_CER}"
    echo "Linux/macOS/Firefox (PEM): ${CERT_PEM}"
    ;;
  excepcion)
    action="${2:-list}"
    ensure_exceptions_file
    case "$action" in
      add)
        ip="${3:-}"
        if ! valid_ip "$ip"; then echo "Uso: horus excepcion add <IP>"; exit 2; fi
        grep -Fxq "$ip" "${EXCEPTIONS_FILE}" 2>/dev/null || echo "$ip" >> "${EXCEPTIONS_FILE}"
        add_bypass_rules "$ip"
        echo "IP ${ip} anadida a excepciones"
        ;;
      remove)
        ip="${3:-}"
        if ! valid_ip "$ip"; then echo "Uso: horus excepcion remove <IP>"; exit 2; fi
        tmpfile=$(mktemp)
        grep -Fxv "$ip" "${EXCEPTIONS_FILE}" > "$tmpfile" || true
        mv "$tmpfile" "${EXCEPTIONS_FILE}" && chmod 600 "${EXCEPTIONS_FILE}"
        del_bypass_rules "$ip"
        echo "IP ${ip} eliminada de excepciones"
        ;;
      list)
        [ -s "${EXCEPTIONS_FILE}" ] && cat "${EXCEPTIONS_FILE}" || echo "No hay excepciones configuradas"
        ;;
      *) echo "Uso: horus excepcion [add|remove|list] <IP>"; exit 2 ;;
    esac
    ;;
  install-cert)
    if [ -z "${2:-}" ]; then echo "Uso: horus install-cert /ruta/al/mitmproxy-ca-cert.cer"; exit 2; fi
    cp "$2" "${CERT_CER}" && chmod 644 "${CERT_CER}" && echo "Cert copiado a ${CERT_CER}"
    ;;
  actualizar) update_horus ;;
  uninstall) do_uninstall ;;
  help|--help|-h|*) print_help ;;
esac
WRAP

chmod +x /usr/local/bin/horus
command -v dos2unix >/dev/null 2>&1 && dos2unix /usr/local/bin/horus || true
ln -sf /usr/local/bin/horus /usr/bin/horus

cat > "${WRAPPER_PURGE}" <<'PURGE'
#!/usr/bin/env bash
exec /usr/local/bin/horus uninstall
PURGE
chmod 755 "${WRAPPER_PURGE}"

# ---------------------------
# 10) Final
# ---------------------------
echo "==== Instalacion completada ===="
echo " - Horus instalado en: ${HORUS_DIR}"
echo " - Servicio systemd: horus.service"
echo " - Wrapper: ${WRAPPER} (usa 'horus -h') y symlink /usr/bin/horus"
echo " - Logs: ${LOG_DIR}/http_access.log, ${LOG_DIR}/http_wazuh.json, ${LOG_DIR}/ssh_access.log"
echo
echo "Para Wazuh Agent, agrega en /var/ossec/etc/ossec.conf:"
echo "<localfile>"
echo "  <location>${LOG_DIR}/http_wazuh.json</location>"
echo "  <log_format>json</log_format>"
echo "  <label key=\"@source\">horus</label>"
echo "  <label key=\"integration\">horus-mitm</label>"
echo "</localfile>"
echo
echo "Certificados para distribuir a los clientes VPN:"
echo " - Windows (formato CER/DER): ${CERT_CER_DST}"
echo " - Linux/macOS/Firefox (formato PEM): ${CERT_PEM_DST}"
echo
echo "Instala el CERT correspondiente como 'Autoridad de certificacion raiz de confianza' y reinicia el navegador."
systemctl status horus --no-pager -l || true
journalctl -u horus -n 50 --no-pager -l || true
