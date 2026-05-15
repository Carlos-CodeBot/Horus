# Horus

Horus es una herramienta de monitoreo para entornos VPN autorizados. Su objetivo es centralizar trazas de navegacion HTTP/HTTPS y actividad SSH generada por clientes conectados a una red VPN o segmento controlado.

La herramienta instala un servicio `systemd` que levanta `mitmproxy` en modo transparente para HTTP/HTTPS, configura reglas de `iptables` para redirigir trafico web hacia el proxy y genera logs planos y JSON compatibles con integraciones tipo Wazuh. Tambien incorpora un watcher SSH que registra accesos SSH locales al servidor Horus y conexiones SSH que atraviesan Horus hacia otras maquinas dentro de la red/VPN.

> Usa Horus solo en redes, laboratorios, VPNs y equipos donde tengas autorizacion explicita para monitorear trafico.

## Que hace

Horus instala y configura los siguientes componentes:

- Un entorno Python virtual en `/opt/horus/venv`.
- `mitmproxy` en modo transparente para interceptar y registrar trafico HTTP/HTTPS.
- Addons Python para generar logs HTTP planos y eventos JSON compatibles con Wazuh.
- Un watcher SSH para registrar accesos locales y conexiones SSH remotas vistas en la VPN.
- Reglas de `iptables` para redirigir HTTP/HTTPS y registrar conexiones SSH remotas.
- Un servicio `systemd` llamado `horus.service`.
- Un wrapper de administracion llamado `horus`.
- Soporte para tres modos de certificados: CA generada automaticamente, CA propia y certificado wildcard.

## Arquitectura general

```text
Cliente VPN ── HTTP/HTTPS ──> Horus/iptables ──> mitmproxy ──> Destino
Cliente VPN ── SSH:22 ──────> Horus/iptables ──> Destino SSH
                              │
                              ├─ /var/log/horus/http_access.log
                              ├─ /var/log/horus/http_wazuh.json
                              └─ /var/log/horus/ssh_access.log
```

Para HTTP y HTTPS, Horus usa reglas NAT en `PREROUTING` para redirigir puertos `80` y `443` al puerto local `8080`, donde escucha `mitmproxy`.

Para SSH, Horus no descifra el protocolo. SSH esta cifrado de extremo a extremo. El watcher registra dos tipos de eventos:

- `LOCAL_SSH`: autenticaciones SSH que entran directamente al servidor donde corre Horus. En este caso se puede registrar usuario y resultado `ACCEPTED` o `FAILED`, porque esa informacion viene de `sshd.service` o `/var/log/auth.log`.
- `REMOTE_SSH`: conexiones TCP nuevas hacia puerto `22` que atraviesan Horus por la VPN hacia otras maquinas. En este caso se registra origen, destino, puerto origen y puerto destino, pero no usuario ni exito de autenticacion remota, porque esos datos viven en los logs del servidor destino.

## Requisitos

- Servidor Linux con permisos de `root`.
- `systemd`.
- `iptables`.
- `python3` y `pip`.
- Conectividad a internet durante la instalacion para instalar dependencias y descargar paquetes Python.
- Una interfaz de red/VPN identificable, por ejemplo `tun0`, `tap0`, `eth0`, `ens...` o `wlan...`.
- Clientes autorizados en los que se pueda instalar la CA de Horus si se desea inspeccionar HTTPS.

En Rocky Linux/RHEL/Fedora, el instalador usa `dnf`. En Debian/Ubuntu, usa `apt-get`.

## Instalacion rapida

Clona el repositorio y ejecuta el instalador como `root`:

```bash
git clone https://github.com/Carlos-CodeBot/Horus.git
cd Horus
chmod +x Instalador_Horus.sh
sudo ./Instalador_Horus.sh
```

Durante la instalacion Horus detecta automaticamente una interfaz `tun`, `tap`, `eth`, `en`, `ens` o `wlan`. Si no detecta una interfaz valida, solicita una manualmente.

Tambien detecta el prefijo `/24` de la VPN a partir de la IP de la interfaz. Por ejemplo, si la interfaz tiene `192.168.2.1`, Horus usara `192.168.2.0/24`.

> Nota: la version integrada del instalador conserva la base con Wazuh/wildcard y aplica automaticamente la mejora de SSH remoto al finalizar. No es necesario ejecutar parches adicionales.

## Opciones de certificados durante la instalacion

Durante la instalacion aparece el menu:

```text
===== OPCION CA =====
1) Generar CA automaticamente (recomendado)
2) Usar CA + KEY existentes (tu entregas rutas absolutas)
3) Usar certificado wildcard existente (*.dominio)
```

### Opcion 1: generar CA automaticamente

Esta es la opcion recomendada para laboratorios y despliegues controlados.

Horus intenta generar la CA usando `mitmproxy`. Si `mitmproxy` no logra generar la CA, el instalador usa un fallback con `OpenSSL`.

Archivos resultantes:

```text
/opt/horus/mitmproxy-ca-cert.pem
/opt/horus/mitmproxy-ca-cert.cer
```

Uso recomendado:

- Instalar el archivo `.cer` en Windows como entidad de certificacion raiz de confianza.
- Instalar el archivo `.pem` en Linux, macOS, Firefox u otros clientes que acepten CA en PEM.

### Opcion 2: usar una CA propia

Usa esta opcion si ya tienes una CA interna autorizada para el laboratorio o la organizacion.

El instalador solicita:

```text
CERT PEM (CA o PEM combinado)
KEY (si el CERT no incluye la KEY)
```

Requisitos:

- El certificado debe ser una CA valida, es decir, debe tener `CA:TRUE`.
- Si el PEM no incluye la llave privada, debes entregar la ruta de la llave por separado.
- El instalador genera el archivo combinado necesario para que `mitmproxy` pueda firmar certificados dinamicamente.

Ejemplo de rutas:

```text
/root/ca-horus.pem
/root/ca-horus.key
```

Esta opcion es util cuando quieres que los clientes confien en una CA corporativa o de laboratorio ya distribuida.

### Opcion 3: usar certificado wildcard existente

Usa esta opcion si ya tienes un certificado wildcard valido, por ejemplo:

```text
*.example.com
```

El instalador solicita:

```text
Dominio wildcard: *.example.com
Ruta CERT: /root/wildcard.crt
Ruta FULLCHAIN: /root/fullchain.pem
Ruta KEY: /root/wildcard.key
```

Requisitos:

- El certificado debe estar en formato PEM.
- La llave privada debe corresponder al certificado.
- El instalador valida que el certificado y la llave coincidan.
- Se genera un PEM combinado en:

```text
/opt/horus/mitmproxy-wildcard.pem
```

Cuando se usa wildcard, Horus arranca `mitmproxy` con el parametro `--certs` para cargar el certificado wildcard:

```text
*= /opt/horus/mitmproxy-wildcard.pem
```

En la implementacion real se usa sin espacio:

```text
*=/opt/horus/mitmproxy-wildcard.pem
```

Esta opcion es util cuando quieres interceptar dominios cubiertos por tu wildcard autorizado. No reemplaza la necesidad de autorizacion ni evita restricciones como certificate pinning.

## Instalacion de la CA en clientes

Para que la inspeccion HTTPS funcione, los clientes autorizados deben confiar en la CA o certificado usado por Horus.

### Windows

Usa el archivo:

```text
/opt/horus/mitmproxy-ca-cert.cer
```

Instalalo en:

```text
Equipo local > Entidades de certificacion raiz de confianza
```

Despues reinicia el navegador.

### Linux

Usa el archivo:

```text
/opt/horus/mitmproxy-ca-cert.pem
```

Ejemplo en Debian/Ubuntu:

```bash
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/horus.crt
sudo update-ca-certificates
```

Ejemplo en Rocky/RHEL/Fedora:

```bash
sudo cp mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/horus.pem
sudo update-ca-trust
```

### Firefox

Firefox puede usar su propio almacen de certificados. Importa el PEM desde:

```text
Ajustes > Privacidad y seguridad > Certificados > Ver certificados > Autoridades > Importar
```

Marca la opcion para confiar en la CA para identificar sitios web.

## Archivos instalados

| Ruta | Descripcion |
| --- | --- |
| `/opt/horus/horus.py` | Proceso principal que levanta mitmproxy, watcher SSH y reglas iptables. |
| `/opt/horus/mitm_simple_logger.py` | Addon mitmproxy para log HTTP plano. |
| `/opt/horus/mitm_wazuh_logger.py` | Addon mitmproxy para eventos JSON estilo Wazuh. |
| `/opt/horus/ssh_log_watcher.py` | Watcher de SSH local y remoto. |
| `/opt/horus/exceptions.txt` | Lista de IPs destino excluidas de la intercepcion HTTP/HTTPS. |
| `/opt/horus/mitmproxy-ca-cert.pem` | Certificado CA en formato PEM. |
| `/opt/horus/mitmproxy-ca-cert.cer` | Certificado CA en formato CER/DER para Windows. |
| `/opt/horus/mitmproxy-wildcard.pem` | PEM combinado del wildcard, solo si se usa la opcion wildcard. |
| `/etc/systemd/system/horus.service` | Servicio systemd. |
| `/usr/local/bin/horus` | Wrapper de administracion. |

## Logs

Horus escribe sus logs en `/var/log/horus`.

### HTTP plano

Archivo:

```text
/var/log/horus/http_access.log
```

Formato aproximado:

```text
fecha_utc    ip_cliente    host_destino    ip_destino    puerto    metodo    ruta    url    codigo_http
```

Ejemplo:

```text
2026-05-15 12:10:01    192.168.2.15    example.com    93.184.216.34    443    GET    /    https://example.com/    200
```

### HTTP JSON para Wazuh

Archivo:

```text
/var/log/horus/http_wazuh.json
```

Cada linea es un evento JSON con campos como:

- `timestamp`
- `event.module`
- `event.dataset`
- `event.kind`
- `event.category`
- `event.type`
- `event.outcome`
- `event.risk`
- `source.ip`
- `source.port`
- `destination.ip`
- `destination.port`
- `destination.domain`
- `http.request.method`
- `http.response.status_code`
- `url.full`
- `user_agent.original`
- `horus.log_type`

Ejemplo de configuracion para Wazuh Agent:

```xml
<localfile>
  <location>/var/log/horus/http_wazuh.json</location>
  <log_format>json</log_format>
  <label key="@source">horus</label>
  <label key="integration">horus-mitm</label>
</localfile>
```

### SSH

Archivo:

```text
/var/log/horus/ssh_access.log
```

Ejemplos:

```text
2026-05-15 12:10:01    192.168.2.15    ACCEPTED    root    LOCAL_SSH    -    ...
2026-05-15 12:11:30    192.168.2.15    CONNECT     -       REMOTE_SSH   192.168.2.80:22    SPT=54321    PROTO=TCP    ...
```

Campos principales:

| Campo | Significado |
| --- | --- |
| Fecha UTC | Momento en que Horus registro el evento. |
| IP origen | Cliente VPN que origina la conexion. |
| Evento | `ACCEPTED`, `FAILED` o `CONNECT`. |
| Usuario | Usuario SSH cuando el acceso es local; `-` en conexiones remotas. |
| Tipo | `LOCAL_SSH` o `REMOTE_SSH`. |
| Destino | Para `REMOTE_SSH`, IP destino y puerto `22`. |
| SPT | Puerto origen de la conexion TCP remota. |
| PROTO | Protocolo reportado por kernel, normalmente `TCP`. |

## Comandos disponibles

```bash
horus start
horus stop
horus restart
horus status
horus logs
horus certpath
horus excepcion add <IP>
horus excepcion remove <IP>
horus excepcion list
horus actualizar
horus install-cert /ruta/al/mitmproxy-ca-cert.cer
horus uninstall
```

### Ver logs

```bash
horus logs
```

Muestra los ultimos eventos HTTP, JSON Wazuh y SSH.

### Ver certificados

```bash
horus certpath
```

Muestra las rutas de los certificados generados o copiados por Horus:

- CER/DER para Windows.
- PEM para Linux, macOS o Firefox.

Para inspeccion HTTPS, instala el certificado correspondiente como autoridad raiz de confianza en los clientes autorizados.

### Excluir destinos HTTP/HTTPS

Puedes excluir una IP destino de la intercepcion HTTP/HTTPS:

```bash
horus excepcion add 192.168.2.80
```

Para quitarla:

```bash
horus excepcion remove 192.168.2.80
```

Las excepciones se guardan en:

```text
/opt/horus/exceptions.txt
```

Las excepciones aplican a HTTP/HTTPS. No desactivan el registro de conexiones SSH remotas hacia TCP/22.

## Reglas de red que usa Horus

Horus agrega reglas de `iptables` para:

- Redirigir trafico TCP `80` y `443` desde la VPN hacia `mitmproxy`.
- Registrar conexiones TCP nuevas hacia `22` en la cadena `FORWARD` con prefijo de kernel `HORUS_SSH_REMOTE`.
- Habilitar forwarding IPv4 con `net.ipv4.ip_forward=1`.

Cuando se detiene, reinicia o desinstala Horus usando el wrapper, se intentan limpiar las reglas creadas por la herramienta.

Comandos utiles para revisar reglas:

```bash
sudo iptables -t nat -S PREROUTING
sudo iptables -S FORWARD | grep HORUS_SSH_REMOTE
```

## Validacion despues de instalar

Revisa el servicio:

```bash
sudo systemctl status horus --no-pager
```

Revisa logs en tiempo real:

```bash
sudo tail -f /var/log/horus/http_access.log
sudo tail -f /var/log/horus/http_wazuh.json
sudo tail -f /var/log/horus/ssh_access.log
```

Pruebas sugeridas:

1. Desde un cliente VPN, navega a un sitio HTTP/HTTPS autorizado y revisa `http_access.log` y `http_wazuh.json`.
2. Desde un cliente VPN, conectate por SSH al servidor Horus y revisa eventos `LOCAL_SSH`.
3. Desde un cliente VPN, conectate por SSH a otra maquina enrutable a traves de Horus y revisa eventos `REMOTE_SSH`.

## Limitaciones importantes

- Horus no rompe ni descifra SSH. Para conexiones `REMOTE_SSH` solo registra metadata de conexion: origen, destino y puerto.
- Para saber usuario y resultado de autenticacion en maquinas remotas, se deben recolectar logs del `sshd` de cada maquina destino.
- La inspeccion HTTPS requiere que los clientes autorizados confien en la CA generada, la CA propia o el certificado usado por Horus.
- Algunas aplicaciones con certificate pinning pueden fallar o no ser inspeccionables.
- Un certificado wildcard solo cubre los dominios para los que fue emitido. No permite inspeccionar cualquier dominio arbitrario.
- La herramienta requiere permisos de root por el uso de `iptables`, `systemd`, `journalctl` y captura transparente.

## Desinstalacion

```bash
sudo horus uninstall
```

Esto detiene el servicio, limpia reglas conocidas de `iptables`, elimina archivos en `/opt/horus`, logs en `/var/log/horus`, certificados mitmproxy locales y wrappers instalados.

## Uso responsable

Horus esta pensado para laboratorios, auditorias internas, redes propias, equipos controlados o ambientes donde exista autorizacion. No debe usarse para interceptar trafico de terceros sin consentimiento.
