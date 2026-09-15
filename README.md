# v3ctorlabs Privacy Connection Dashboard

Dashboard de escritorio para manejar perfiles de proxy, Tor local y VPN.

## Ejecutar

```bash
cd /home/vik/privacy-connection-dashboard
./app.py
# o: python3 app.py
```

## Que hace

- Busca proxies gratuitos desde fuentes publicas preconfiguradas.
- Filtra por protocolo, pais, anonimato, uptime minimo, latencia maxima y limite.
- Permite marcar `Solo paises con proteccion de datos laxa/sin ley integral`.
- Importa proxies desde `.txt` o `.csv`.
- Importa proxies desde una URL que pegues manualmente.
- Muestra proveedor, anonimato, uptime, velocidad/latencia de fuente, riesgo legal y estado local.
- Muestra la IP publica visible, geolocalizacion, ASN, ISP, rDNS y flags proxy/VPN/Tor/hosting.
- Amplia la ficha IP con region, ciudad, barrio/distrito, plaza, calle, carretera/road, codigo postal, ISP, empresa registrada, dominio y red CIDR cuando existen.
- Enriquece las coordenadas con OpenStreetMap/Nominatim para etiquetas de calle y barrio estimadas; nunca presenta una IP como domicilio exacto.
- Resalta de forma llamativa la IP publica que estas publicando hacia Internet.
- Mantiene un HUD flotante siempre visible arriba a la derecha con IP publica expuesta, direccion de salida, geolocalizacion, pais/mundo y estado protegido.
- Muestra en grande `IP PROTEGIDA: SI/NO`, la IP publica, direccion geo completa estimada y contador de historial.
- Guarda historial de cambios de IP publica con tiempo desde cada cambio observado.
- El historial conserva snapshots completos de IP, ISP, region, ciudad, barrio, calle/road, coordenadas, flags y primer/ultimo visto.
- El historial queda limitado a 500 IPs por defecto; puedes cambiarlo con `V3CTORLABS_MAX_IP_HISTORY`.
- Genera mapa local con OpenStreetMap para la IP actual con estilo oscuro `v3ctorlabs`.
- Genera un globo del mundo interactivo local para IP publica, historial e IPs de proxies geolocalizadas.
- Muestra un globo animado dentro del dashboard con campo estelar, halo, reticula, pulsos y rutas entre nodos.
- El globo pequeno anima paquetes que recorren las rutas desde la IP publica y marca `LINK LIVE/STANDBY`.
- Lee en modo solo lectura la interfaz de salida, Wi-Fi/SSID si el sistema lo expone, DNS, interfaces y conexiones NetworkManager.
- Incluye una guia paso a paso para los primeros 100 usos: configurar, testear, verificar alcance, revisar huella y proponer mejoras.
- La guia avanza automaticamente despues de cada paso y termina con una alerta visual `LINK LIVE`, estado verde, pulgar arriba y aplausos.
- El boton `MAPA LINK LIVE` abre el globo y mapa con badge vivo, IP actual, rutas geo, nodos, historial difuminado y estado `GEO ROUTE ACTIVE`.
- Incluye `Pagar lifetime 5+ EUR` con Checkout de Stripe configurable mediante `V3CTORLABS_STRIPE_PAYMENT_LINK`.
- La ventana `Metodos de pago` lista Visa/Mastercard credito o debito, SEPA EUR, Bizum y stablecoin/USDC en Solana cuando Stripe los habilita.
- Bitcoin nativo y SOL nativo se tratan como enlaces externos opcionales, no como metodos Stripe garantizados.
- Genera un informe de huella digital separando datos medidos, posibles observables del navegador y limites del dashboard.
- Conserva memoria local de sesiones guiadas, telemetria, tests e historial para recomendar mejoras operativas.
- `Aplicar mejoras` ejecuta las recomendaciones seguras detectadas: defaults, perfil seleccionable, ProxyChains, test, guardado, telemetria, IP e historial; deja en el log las verificaciones manuales pendientes.
- En el globo grande puedes arrastrar para rotar, usar rueda para zoom y pulsar una IP para ver detalle, mapa con zoom y enlace a Google Maps.
- El globo grande incluye HUD con nodos geo, historial, proxies, rutas luminosas desde la IP visible y filas clicables.
- Los puntos de historial antiguo aparecen difuminados para distinguirlos de la IP actual.
- Permite abrir detalle completo de conexion visible y perfil seleccionado.
- Incluye `Guia proxies` dinamica dentro del dashboard: selecciona HTTP, HTTPS, SOCKS4, SOCKS5, Tor, WireGuard, OpenVPN, transparente, anonymous, elite, reverse, rotativo, residencial o datacenter.
- La guia permite aplicar el tipo al perfil seleccionado, aplicar filtros de busqueda, cambiar el uso recomendado o activar `Todos los tipos`.
- Usa tema ciberpunk `v3ctorlabs` con paneles oscuros, acentos neon y registro visible firmado.
- Mantiene una consola fija inferior con las 5 ultimas lineas y registra cada click de boton como `CLICK: ...`; `Abrir log completo` muestra el historial persistente.
- Guarda un registro local de acciones en `~/.local/share/privacy-connection-dashboard/v3ctorlabs-registro.log`.
- Genera comandos y snippet para ProxyChains, torsocks y torify.
- Escribe `proxychains.conf` local y lanza Chromium con ProxyChains o torsocks.
- Puede enviar `SIGNAL NEWNYM` a Tor ControlPort y repetirlo cada cierto intervalo.
- Incluye `Conectar Tor` rapido: activa perfil Tor, escribe ProxyChains, prueba Tor, pide NEWNYM y refresca IP.
- Incluye `VPN facil`: importa/sube WireGuard/OpenVPN mediante NetworkManager (`nmcli`) si esta disponible.
- Incluye botones ON/OFF para Proton VPN y Surfshark cuando sus clientes CLI estan disponibles.
- Incluye tres conexiones rapidas de un clic: `Default`, `Pro` y `Agresiva`.
- Cada modo aplica sus filtros, selecciona un perfil, escribe `CONNECTING/LINK LIVE/LINK FAIL` y cambia la paleta completa del dashboard.
- Proton soporta modos `fastest`, `country`, `secure-core`, `tor`, `p2p` y `random`.
- Surfshark intenta usar `surfshark-vpn` o `surfshark`; si el paquete Snap esta bloqueado por AppArmor, usa `VPN facil` con WireGuard/OpenVPN manual.
- Soporta variantes de proxy HTTP, HTTPS, SOCKS4, SOCKS5, Tor, WireGuard y OpenVPN.
- Prueba HTTP/HTTPS con `https://api.ipify.org`.
- Prueba SOCKS5/Tor comprobando que el socket local/remoto responde.
- Mantiene un perfil Tor local para `127.0.0.1:9050` o Tor Browser `9150`.
- Maneja perfiles WireGuard/OpenVPN por archivo `.conf`/`.ovpn`.
- Genera comandos `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` y Chromium con proxy.
- Guarda perfiles localmente o cifrados si tienes `cryptography` instalado.

## Fuentes publicas incluidas

- HProxy: `https://hproxy.com/api/proxy-list`
- ProxyScrape: `https://api.proxyscrape.com/v4/free-proxy-list/get`
- Litport: `https://litport.net/api/free-proxy`
- Databay: `https://databay.com/api/v1/proxy-list`

El filtro recomendado por defecto es `elite,anonymous`, `uptime >= 80%`, `max 800 ms`, `limite 100`.
`Elite` indica que la prueba de cabeceras de la fuente no vio tu IP real; no
garantiza privacidad total, cifrado extremo a extremo, reputacion limpia,
ausencia de logs, ni proteccion contra fingerprinting del navegador.

## Filtro de paises con proteccion de datos laxa

El check usa una lista conservadora editable en `app.py`:
`LAX_DATA_PROTECTION_COUNTRIES`. Incluye paises sin ley nacional integral
aparente o con proteccion federal fragmentaria, segun fuentes publicas como
UNCTAD/IAPP/World Privacy Forum. Es una ayuda operativa, no asesoramiento legal.

## Rotacion Tor

Para que `NEWNYM` funcione, Tor debe tener `ControlPort` activo, normalmente:

```text
ControlPort 9051
CookieAuthentication 1
```

Si usas contrasena en Tor, escribela en el campo `Pass Tor`. La rotacion cambia
el circuito Tor cuando Tor lo permite; no fuerza que todos los sitios olviden
cookies, sesiones o fingerprinting del navegador.

En esta maquina quedo configurado asi:

```text
/etc/tor/torrc
ControlPort 9051
HashedControlPassword ...
CookieAuthentication 1
```

La contrasena local que usa el dashboard se guarda con permisos `600` en:

```text
~/.local/share/privacy-connection-dashboard/tor-control-password
```

El dashboard ya no muestra ni pide esa contrasena para Tor: la usa
automaticamente desde el archivo local. Las credenciales del sistema para VPN
siguen bajo control de Linux/NetworkManager.

## ProxyChains

El boton `Comandos` imprime un bloque compatible con:

```text
~/.proxychains/proxychains.conf
/etc/proxychains4.conf
```

Despues puedes lanzar una app con:

```bash
proxychains4 chromium
```

En esta maquina tambien quedo instalado `proxychains4` y creado:

```text
~/.local/share/privacy-connection-dashboard/proxychains.conf
```

El globo interactivo se genera en:

```text
~/.local/share/privacy-connection-dashboard/ip-globe.html
```

## ON/OFF anonimo

- `Conectar Tor`: activa el perfil Tor local, escribe ProxyChains, solicita una nueva identidad Tor y refresca la IP visible.
- `Proton ON/OFF`: conecta o desconecta Proton VPN segun el estado de `protonvpn status`.
- `Surfshark ON/OFF`: conecta o desconecta Surfshark si su CLI responde.
- `Anon OFF`: desactiva perfiles proxy en el dashboard e intenta desconectar Proton/Surfshark.

El estado grande `ANON ON/OFF` se basa en la geolocalizacion de la IP publica:
marca Tor/VPN/proxy/hosting si la fuente de geolocalizacion lo detecta. No
sustituye una prueba de fugas DNS/WebRTC.

## Guia de primeros usos y alcance

El boton `Guia inicial` aparece durante las primeras 100 sesiones y permite ejecutar
el ciclo recomendado: leer PC/Wi-Fi, consultar IP publica, probar un perfil,
decidir el alcance, revisar la huella y analizar mejoras. Las sesiones y pasos se
guardan en `~/.local/share/privacy-connection-dashboard/onboarding.json`.

## Conexiones rapidas

- `Default`: equilibrio con anonimato elite/anonymous, uptime minimo 80% y maximo 800 ms.
- `Pro`: prioriza Tor/SOCKS5/VPN, anonimato elite, uptime minimo 90% y maximo 500 ms.
- `Agresiva`: acepta todos los protocolos, uptime minimo 60% y maximo 1500 ms para encontrar una ruta operativa.

Los botones cambian el color general del dashboard mientras conectan. Una prueba
correcta cambia el estado a `LINK LIVE`, activa la variante viva de la paleta y
registra el perfil y la futura comprobacion de IP. `Agresiva` puede seleccionar
proxies transparentes si se han importado: revisa siempre la IP publica antes de
usar cuentas o credenciales.

El panel `PC / Wi-Fi` es informativo y no cambia rutas ni contraseñas. Un proxy
HTTP/SOCKS solo afecta a la app que lo usa; `proxychains4`/`torsocks` afectan a las
apps lanzadas con ese comando; una VPN importada por NetworkManager puede cubrir
la ruta completa del PC. Comprueba siempre IP, DNS e IPv6 despues de conectar.

El panel `Huella digital` muestra IP, geo, ASN, ISP, rDNS, flags, DNS local e
historial medidos. Tambien recuerda que un navegador puede exponer User-Agent,
idioma, zona horaria, cookies, WebRTC, canvas/WebGL y almacenamiento local; el
dashboard no mide automaticamente el fingerprint real del navegador.

La memoria de trabajo y las recomendaciones se almacenan localmente en:

```text
~/.local/share/privacy-connection-dashboard/v3ctorlabs-registro.log
~/.local/share/privacy-connection-dashboard/local-telemetry.json
~/.local/share/privacy-connection-dashboard/onboarding.json
```

## Stripe: prueba y lifetime

La app inicia una prueba local de 14 dias. Despues muestra el pago unico lifetime
desde 5 EUR. El enlace de cobro se configura sin guardar claves secretas en la
app:

```bash
export V3CTORLABS_STRIPE_PAYMENT_LINK="https://buy.stripe.com/TU_LINK_REAL"
./app.py
```

En Stripe crea un Payment Link de tipo `Customers choose what to pay`, precio
`One-off`, minimo `5 EUR` y sin maximo configurado. Stripe puede aplicar limites
operativos a los pagos pay-what-you-want; el dashboard de Stripe es la autoridad
para ese limite. Este flujo usa el trial local y luego un pago unico, porque los
trials nativos de Stripe pertenecen a suscripciones y no a una donacion one-off.

Stripe mostrara dinamicamente los metodos compatibles con tu cuenta, pais, moneda
y enlace. Bizum es para clientes compatibles en Espana; SEPA usa cuentas EUR.
Stripe Crypto documenta stablecoins y actualmente requiere elegibilidad de cuenta
para aceptar pagos; no confundas USDC en Solana con SOL o Bitcoin nativos.

Para enlaces externos opcionales:

```bash
export V3CTORLABS_BITCOIN_PAYMENT_LINK="https://tu-procesador-bitcoin/checkout"
export V3CTORLABS_SOLANA_PAYMENT_LINK="https://tu-procesador-solana/checkout"
```

## Selector dinamico de tipos de proxy

El dashboard explica y permite aplicar desde `Guia proxies`:

- HTTP / HTTPS
- SOCKS4 / SOCKS5
- Transparente / Anonymous / Elite
- Reverse o proxy inverso
- Rotativo
- Residencial
- Datacenter
- Tor
- VPN

Resumen corto: `transparente` puede filtrar tu IP real en cabeceras;
`anonymous` oculta IP pero suele revelar que hay proxy; `elite` no muestra
cabeceras obvias de proxy en las pruebas de la fuente; `reverse/inverso` no es
para anonimizar clientes, sino para publicar/proteger servidores.

El boton `Todos tipos` deja la busqueda en `protocolo=all`, `anon=all`,
`uptime >= 60%`, `max 1500 ms` y `limite 200`. Esto incluye proxies
transparentes, asi que revisa siempre la IP visible antes de usar sesiones
sensibles.

En esta maquina se detecto:

```text
protonvpn: /usr/local/bin/protonvpn
surfshark: /snap/bin/surfshark
proxychains4: /usr/bin/proxychains4
torsocks: /usr/bin/torsocks
tor: /usr/sbin/tor
```

`surfshark --help` devolvio un error de confinamiento Snap/AppArmor en esta
sesion. Si ocurre dentro del dashboard, usa perfiles manuales `.conf`/`.ovpn`
con `VPN facil` o repara `snapd.apparmor`.

Prueba rapida:

```bash
proxychains4 -f ~/.local/share/privacy-connection-dashboard/proxychains.conf curl https://check.torproject.org/api/ip
torsocks curl https://check.torproject.org/api/ip
```

## Formato de proxies

Una entrada por linea:

```text
http://1.2.3.4:8080
socks5://5.6.7.8:1080
ES,https,9.9.9.9,3128
```

## Cifrado

Para activar guardado cifrado fuerte:

```bash
python3 -m pip install cryptography
```

El archivo se guarda en:

```text
~/.local/share/privacy-connection-dashboard/profiles.enc
```

## Nota de seguridad

Los proxies gratuitos suelen registrar trafico, inyectar contenido o desaparecer
sin aviso. Para sesiones sensibles usa VPN propia/de confianza o Tor, y evita
enviar credenciales por proxies desconocidos.
