# Horus

Horus es una herramienta de monitoreo para entornos VPN autorizados. Su objetivo es centralizar trazas de navegacion HTTP/HTTPS y actividad SSH generada por clientes conectados a una red VPN o segmento controlado.

La herramienta instala un servicio `systemd` que levanta `mitmproxy` en modo transparente para HTTP/HTTPS, configura reglas de `iptables` para redirigir trafico web hacia el proxy y genera logs planos y JSON compatibles con integraciones tipo Wazuh. Tambien incorpora un watcher SSH que registra tanto accesos SSH locales al servidor Horus como conexiones SSH que atraviesan Horus hacia otras maquinas.

> Usa Horus solo en redes, laboratorios, VPNs y equipos donde tengas autorizacion explicita para monitorear trafico.

## Que hace

Horus instala y configura los siguientes componentes:

- Un entorno Python virtual en `/opt/horus/venv`.
- `mitmproxy` en modo transparente para interceptar y registrar trafico HTTP/HTTPS.
- Addons Python para generar logs HTTP simples y eventos JSON.
- Un watcher SSH para registrar accesos locales y conexiones SSH remotas vistas en la VPN.
- Reglas de `iptables` para redirigir HTTP/HTTPS y registrar intentos SSH remotos.
- Un servicio `systemd` llamado `horus.service`.
- Un wrapper de administracion llamado `horus`.

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
- `REMOTE_SSH`: conexiones TCP nuevas hacia puerto `22` que atraviesan Horus por la VPN hacia otras maquinas. En este caso se registra origen, destino y puerto, pero no usuario ni exito de autenticacion remota, porque esos datos viven en los logs del servidor destino.

## Instalacion

Ejecuta como root:

```bash
chmod +x Instalador_Horus.sh
sudo ./Instalador_Horus.sh
```

Durante la instalacion Horus detecta automaticamente una interfaz `tun`, `tap`, `eth`, `en`, `ens` o `wlan`. Si no detecta una interfaz valida, solicita una manualmente.

Tambien detecta el prefijo `/24` de la VPN a partir de la IP de la interfaz. Por ejemplo, si la interfaz tiene `192.168.2.1`, Horus usara `192.168.2.0/24`.

## Archivos instalados

| Ruta | Descripcion |
| --- | --- |
| `/opt/horus/horus.py` | Proceso principal que levanta mitmproxy, watcher SSH y reglas iptables. |
| `/opt/horus/mitm_simple_logger.py` | Addon mitmproxy para log HTTP plano. |
| `/opt/horus/mitm_wazuh_logger.py` | Addon mitmproxy para eventos JSON estilo Wazuh. |
| `/opt/horus/ssh_log_watcher.py` | Watcher de SSH local y remoto. |
| `/opt/horus/exceptions.txt` | Lista de IPs destino excluidas de la intercepcion HTTP/HTTPS. |
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
- `source.ip`
- `destination.ip`
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
2026-05-15 12:10:01    192.168.2.15    ACCEPTED    root    LOCAL_SSH    ...
2026-05-15 12:11:30    192.168.2.15    CONNECT     -       REMOTE_SSH   192.168.2.80:22    SPT=54321    ...
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

Muestra las rutas de los certificados generados por mitmproxy:

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

## Reglas de red que usa Horus

Horus agrega reglas de `iptables` para:

- Redirigir trafico TCP `80` y `443` desde la VPN hacia `mitmproxy`.
- Registrar conexiones TCP nuevas hacia `22` en la cadena `FORWARD` con prefijo de kernel `HORUS_SSH`.
- Habilitar forwarding IPv4 con `net.ipv4.ip_forward=1`.

Cuando se detiene o desinstala Horus usando el wrapper, se intentan limpiar las reglas creadas por la herramienta.

## Limitaciones importantes

- Horus no rompe ni descifra SSH. Para conexiones `REMOTE_SSH` solo registra metadata de conexion: origen, destino y puerto.
- Para saber usuario y resultado de autenticacion en maquinas remotas, se deben recolectar logs del `sshd` de cada maquina destino.
- La inspeccion HTTPS requiere que los clientes autorizados confien en la CA generada por mitmproxy.
- Algunas aplicaciones con certificate pinning pueden fallar o no ser inspeccionables.
- La herramienta requiere permisos de root por el uso de `iptables`, `systemd`, `journalctl` y captura transparente.

## Desinstalacion

```bash
sudo horus uninstall
```

Esto detiene el servicio, limpia reglas conocidas de `iptables`, elimina archivos en `/opt/horus`, logs en `/var/log/horus`, certificados mitmproxy locales y wrappers instalados.

## Uso responsable

Horus esta pensado para laboratorios, auditorias internas, redes propias, equipos controlados o ambientes donde exista autorizacion. No debe usarse para interceptar trafico de terceros sin consentimiento.
