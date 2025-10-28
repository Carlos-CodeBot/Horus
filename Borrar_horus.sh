#!/usr/bin/env bash
# Borrar_horus.sh
# Desinstala completamente Horus y limpia reglas/archivos/procesos residuales.
# Ejecutar como root.

set -euo pipefail
IFS=$'\n\t'

HORUS_DIR="/opt/horus"
LOG_DIR="/var/log/horus"
UNIT="/etc/systemd/system/horus.service"
WRAPPER="/usr/local/bin/horus"
WRAPPER_LINK="/usr/bin/horus"
PROFILE_PATH="/etc/profile.d/horus_path.sh"
MITMPROXY_DIR="/root/.mitmproxy"

echo "==== Desinstalador Horus (purga total) ===="

if [ "$(id -u)" -ne 0 ]; then
  echo "Este script necesita permisos de root. Ejecuta con sudo." >&2
  exit 1
fi

# ------------------------------------------------------------------------------
# 1) Detener/Deshabilitar servicio y limpiar systemd
# ------------------------------------------------------------------------------
if systemctl list-unit-files | grep -q '^horus\.service'; then
  echo "-> Deteniendo servicio horus..."
  systemctl stop horus.service 2>/dev/null || true
  systemctl disable horus.service 2>/dev/null || true
  systemctl reset-failed horus.service 2>/dev/null || true
fi

if [ -f "$UNIT" ]; then
  echo "-> Eliminando unit file: $UNIT"
  rm -f "$UNIT"
fi

# ------------------------------------------------------------------------------
# 2) Matar procesos residuales (por si quedó algo colgado)
# ------------------------------------------------------------------------------
echo "-> Matando procesos residuales (horus/mitmdump/ssh_log_watcher/flow_sniffer)..."
pkill -f "/opt/horus/horus.py" 2>/dev/null || true
pkill -f "mitmdump" 2>/dev/null || true
pkill -f "/opt/horus/ssh_log_watcher.py" 2>/dev/null || true
pkill -f "/opt/horus/flow_sniffer.py" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 3) Quitar reglas NAT (80/443) añadidas por Horus
#     Intentamos leer IF_IN y VPN_NET de horus.py para borrar exactamente las reglas
# ------------------------------------------------------------------------------
IF_IN=""; VPN_NET=""
if [ -f "${HORUS_DIR}/horus.py" ]; then
  IF_IN=$(awk -F'=' '/^IF_IN[[:space:]]*=/{gsub(/"| /,"",$2); print $2}' "${HORUS_DIR}/horus.py" || true)
  VPN_NET=$(awk -F'=' '/^VPN_NET[[:space:]]*=/{gsub(/"| /,"",$2); print $2}' "${HORUS_DIR}/horus.py" || true)
fi

del_rule_iptables() {
  local dport="$1"
  if [ -n "$IF_IN" ] && [ -n "$VPN_NET" ] && command -v iptables >/dev/null 2>&1; then
    if iptables -t nat -C PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport "$dport" -j REDIRECT --to-ports 8080 2>/dev/null; then
      echo "-> Borrando regla iptables PREROUTING dport $dport ..."
      iptables -t nat -D PREROUTING -i "$IF_IN" -s "$VPN_NET" -p tcp --dport "$dport" -j REDIRECT --to-ports 8080 || true
    fi
  fi
}

# Si el sistema usa nftables, no tocamos reglas (Horus instala con iptables-nft).
# Sólo limpiamos iptables si existiesen.
echo "-> Limpiando reglas NAT (iptables) si existen..."
del_rule_iptables 80
del_rule_iptables 443

# ------------------------------------------------------------------------------
# 4) Borrar wrapper, symlink y helper de PATH
# ------------------------------------------------------------------------------
if [ -f "$WRAPPER" ]; then
  echo "-> Eliminando wrapper: $WRAPPER"
  rm -f "$WRAPPER"
fi
if [ -L "$WRAPPER_LINK" ] || [ -f "$WRAPPER_LINK" ]; then
  echo "-> Eliminando symlink: $WRAPPER_LINK"
  rm -f "$WRAPPER_LINK"
fi
if [ -f "$PROFILE_PATH" ]; then
  echo "-> Eliminando profile PATH helper: $PROFILE_PATH"
  rm -f "$PROFILE_PATH"
fi

# ------------------------------------------------------------------------------
# 5) Borrar directorios /opt/horus y /var/log/horus
# ------------------------------------------------------------------------------
if [ -d "$HORUS_DIR" ]; then
  echo "-> Eliminando directorio: $HORUS_DIR"
  rm -rf "$HORUS_DIR"
fi
if [ -d "$LOG_DIR" ]; then
  echo "-> Eliminando logs: $LOG_DIR"
  rm -rf "$LOG_DIR"
fi

# ------------------------------------------------------------------------------
# 6) (Opcional) Borrar CA/KEY generadas por mitmproxy del root
# ------------------------------------------------------------------------------
read -r -p "¿Deseas borrar también ${MITMPROXY_DIR} (CA/KEY de mitmproxy del root)? [y/N]: " PURGE_MITM
PURGE_MITM=${PURGE_MITM:-N}
if [[ "$PURGE_MITM" =~ ^[Yy]$ ]]; then
  if [ -d "$MITMPROXY_DIR" ]; then
    echo "-> Eliminando ${MITMPROXY_DIR}"
    rm -rf "$MITMPROXY_DIR"
  else
    echo "-> No existe ${MITMPROXY_DIR}, nada que borrar."
  fi
else
  echo "-> Conservando ${MITMPROXY_DIR}"
fi

# ------------------------------------------------------------------------------
# 7) Refrescar systemd (cache) y limpiar fallas
# ------------------------------------------------------------------------------
echo "-> Refrescando cache de systemd y limpiando fallas..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl reset-failed

# ------------------------------------------------------------------------------
# 8) Mensajes finales + verificación
# ------------------------------------------------------------------------------
echo "==== Desinstalación completada ===="
echo "Se removieron servicio, procesos, reglas NAT (si existían), binarios, venv y logs."
echo
echo "Verificaciones rápidas:"
echo "  systemctl status horus.service   # debería decir: Unit horus.service could not be found."
echo "  ls /opt/horus /var/log/horus     # no debería existir"
echo
echo "NOTA: Si activaste 'net.ipv4.ip_forward=1' SOLO para Horus y quieres revertirlo:"
echo "      sysctl -w net.ipv4.ip_forward=0   (temporal)  |  ajusta /etc/sysctl.conf para persistente."
