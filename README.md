# ObsidianCyber — MVP 0.4 · piloto comercial configurable

ObsidianCyber es un MVP defensivo para una **revisión pasiva, limitada y autorizada de exposición digital**. Esta versión mejora el expediente visual, añade cronología/procedencia de evidencias, permite enriquecimiento opcional local GeoIP y reputación IP mediante AbuseIPDB, y deja preparado un flujo de pedido/Checkout. No es una plataforma SaaS endurecida para producción y **los pagos permanecen desactivados por defecto**.

## Qué está implementado

- Landing adaptable en español con el emblema gráfico del proyecto.
- Ficha de inteligencia estilo dossier: referencia de caso, alcance y cobertura, cronología de evidencias con hora/fuente/confianza, reglas y contribuciones del score, contexto por IP, acciones sugeridas, módulos no conectados y fuentes.
- Muestra pública (`sample-report.html`) con banner explícito: todos sus datos son ficticios y no provienen de un análisis real.
- Backend Python local, `GET /api/health` y endpoints separados para análisis, pedido, verificación DNS TXT, Checkout y recuperación del informe pagado.
- DNS público y máximo de cuatro comprobaciones TLS/HTTPS en el puerto 443 por ejecución. No hay enumeración de puertos, crawling, explotación ni escaneo de vulnerabilidades.
- Score de atención TLS explicable por regla. No es una nota global de seguridad ni una puntuación de reputación IP; GeoIP y reputación de terceros no se suman a ese score. Un score 0 no acredita que un activo sea seguro.
- Cronología de evidencias con nivel de confianza contextual por fuente.
- Enriquecimiento GeoIP local opcional para país/región/ciudad/coordenadas aproximadas y ASN/proveedor, si están disponibles en bases MMDB configuradas.
- Enriquecimiento opcional AbuseIPDB API v2, solo si hay API key y el comprador acepta expresamente compartir las IP comprobadas. Resultado de proveedor separado del score TLS y marcado para validación humana; contexto de CDN/hosting compartido no atribuye actividad maliciosa al cliente.
- Pedido comercial y Stripe Checkout hospedado preparados: verificación de control de dominio por TXT antes del pago; se genera el informe cuando el backend confirma con Stripe que el pago está completado; el informe se puede recuperar con un token de acceso de pedido.
- SQLite local con conservación configurable (por defecto, 30 días); la purga de registros caducados sucede al procesar nuevas peticiones, no mediante una tarea programada en segundo plano.
- Scripts `run.sh` y `test.sh`; pruebas offline con datos/proveedores simulados.

## Estado real: qué funciona y qué no

El análisis base DNS/TLS funciona si hay conectividad. GeoIP funciona solo con una base local compatible y autorizada; no se ha incluido ninguna base de datos en el ZIP. AbuseIPDB funciona solo si configuras una API key válida, tienes un plan/términos compatibles con el uso comercial y el usuario autoriza la consulta. La comprobación de correo comprometido, dark web, buscadores/Google, scraping, monitorización programada y correlación con feeds IoC no están conectados. La ficha muestra estas limitaciones explícitamente.

La oferta piloto muestra un precio propuesto de 79 EUR, configurable; no es un precio de mercado validado ni una promesa de resultados. La muestra es ficticia y no debe presentarse como prueba de un análisis real.

## Arranque en Ubuntu / WSL

En la carpeta del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-commercial.txt
./test.sh
./run.sh
```

Abre `http://127.0.0.1:8000/` en el navegador que pueda acceder al entorno local. Si usas una IP de interfaz WSL para depurar, recuerda que eso cambia la interfaz de escucha; **no expongas este servidor local a redes o Internet**. No uses `python3 -m http.server`: serviría el HTML pero no las rutas de API.

Comprobación de estado:

```bash
curl -s http://127.0.0.1:8000/api/health
```

## Configuración de GeoIP

Instala la dependencia opcional:

```bash
source .venv/bin/activate
python -m pip install -r requirements-geoip.txt
```

Después consigue por separado las bases MMDB para las que tengas una licencia apropiada y configura en un `.env` local una o varias rutas absolutas:

```ini
OBSIDIAN_GEOIP_CITY_DB=/ruta/permitida/GeoIP2-City.mmdb
OBSIDIAN_GEOIP_COUNTRY_DB=/ruta/permitida/GeoIP2-Country.mmdb
OBSIDIAN_GEOIP_ASN_DB=/ruta/permitida/GeoLite2-ASN.mmdb
```

No guardes las bases, licencias o credenciales en Git ni las incluyas en el ZIP. **Comprueba el contrato de licencia antes de mostrar datos en informes vendidos a terceros.** Por ejemplo, las condiciones estándar de algunas bases gratuitas pueden restringir la redistribución o la exhibición de resultados a clientes y puede requerirse una licencia comercial diferente. Las ubicaciones IP son aproximadas y pueden apuntar a un CDN, proxy, operador o proveedor de alojamiento, no a la ubicación física de la empresa o persona.

## Configurar reputación IP opcional

1. Crea una cuenta/API key del proveedor y revisa las condiciones/plan para el uso previsto en un servicio comercial.
2. Copia `.env.example` a `.env` y establece `OBSIDIAN_ABUSEIPDB_API_KEY` localmente.
3. Arranca el servidor de nuevo.
4. En cada pedido el consentimiento para enviar IP a AbuseIPDB es opcional. Si no se acepta, no se consulta la fuente. Solo se consultan hasta cuatro IP públicas por pedido.

No se llama a AbuseIPDB sin clave y consentimiento. El `abuseConfidenceScore` es una señal de terceros basada en reportes, puede ser histórica o referirse a infraestructura compartida y no es una confirmación forense de que el dominio analizado sea malicioso. Nunca se mezcla con el score TLS.

## Flujo de pago preparado, pero desactivado por defecto

El flujo está implementado en código, pero **no se considera validado en vivo**. Las pruebas automáticas usan mocks para Stripe y simulan el estado de pago; no se ha creado una sesión real de Stripe ni verificado un TXT público contra tu dominio. No actives la venta hasta pasar una prueba end-to-end en modo test.

Antes de habilitarlo necesitas:

1. Cuenta Stripe habilitada para tu negocio y claves en modo test primero.
2. Despliegue con una URL pública HTTPS en un entorno endurecido, con base de datos y aislamiento de clientes. No uses directamente este `ThreadingHTTPServer` local para recibir clientes/secretos de producción.
3. `dnspython` instalado (lo hace `requirements-commercial.txt`) y flujo TXT de verificación probado con un dominio de prueba controlado.
4. Condiciones, política de privacidad, identidad del prestador, contacto, información de impuestos/IVA, cancelaciones/reembolsos y demás información precontractual completadas y revisadas según tu jurisdicción.
5. Revisión de los permisos de uso comercial y tratamiento de datos para cada proveedor externo.
6. Configuración de `.env` (nunca publiques el archivo ni las claves):

```ini
OBSIDIAN_HOST=127.0.0.1
OBSIDIAN_PORT=8000
OBSIDIAN_STRIPE_SECRET_KEY=sk_test_...
OBSIDIAN_PUBLIC_BASE_URL=https://tu-dominio-real.example
OBSIDIAN_REPORT_PRICE_CENTS=7900
OBSIDIAN_REPORT_RETENTION_DAYS=30
OBSIDIAN_COMMERCIAL_TERMS_READY=false
```

La URL de ejemplo debe sustituirse por el dominio real; la extensión `.example` es solo ilustrativa. Mantén `OBSIDIAN_COMMERCIAL_TERMS_READY=false` hasta completar y revisar la documentación comercial e impuestos. Cambia a `true` solo después de completar todas las condiciones anteriores, probar el ciclo de compra y revisar seguridad; no es una certificación ni una garantía de que el sistema esté listo para producción. `OBSIDIAN_ENABLE_FREE_ANALYSIS` debe quedarse en `false` para evitar que usuarios públicos eludan el flujo comercial.

El precio de 79 EUR es configurable y la configuración actual no incluye una integración fiscal ni asesoramiento legal. No aceptes pagos reales antes de decidir si el precio lleva IVA, configurar correctamente ese tratamiento y revisar las obligaciones aplicables. La interfaz no envía informes por email: tras el pago confirmado, los muestra en la página de retorno de Checkout.

## Archivos legales

`terms.html` y `privacy.html` son plantillas con campos pendientes, no textos legales finales. Sustituye todos los marcadores y consigue revisión legal adecuada antes de publicarlas o activar Checkout. No marques `OBSIDIAN_COMMERCIAL_TERMS_READY=true` mientras haya campos pendientes.

## Pruebas y límites

```bash
./test.sh
```

La suite cubre validación de dominios, bloqueo de direcciones no públicas, rutas HTTP, límites TLS, scoring, consentimiento de reputación, creación de pedido, token de acceso y verificación de pago simulada. No realiza análisis de dominios externos ni pagos reales.

Este MVP no tiene todavía cuentas de usuario, autenticación de clientes, controles multi-tenant de producción, envío de email, monitorización periódica, colas de trabajo, webhooks de Stripe, análisis de correo filtrado, búsquedas de Google ni dark web. El borrado de registros caducados se efectúa cuando el servidor procesa nuevas solicitudes, por lo que antes de operar con clientes hace falta un proceso de retención fiable y probado.

El servidor implementa límites de petición, comprobación de origen, timeouts acotados y bloqueo de respuestas DNS no públicas para reducir ciertos riesgos de SSRF. Esto **no sustituye una revisión de seguridad de producción**. No lo publiques directamente en Internet; usa un despliegue adecuado detrás de HTTPS, autenticación, base de datos aislada por cliente, controles de abuso, monitorización y gestión de secretos.
