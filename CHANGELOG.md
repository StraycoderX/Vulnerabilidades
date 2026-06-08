# Changelog

Todas las novedades notables de este proyecto se documentan en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [2.2.1] - 2026-06-08

Tanda de endurecimiento tras una revisión de seguridad/estabilidad/escalabilidad.

### Seguridad

- No se reenvían `Cookie`/`Authorization` en redirecciones hacia **otro origen**
  (evita fuga de credenciales).
- Rangos anti-SSRF ampliados: CGNAT `100.64.0.0/10`, `192.0.0.0/24`,
  benchmark `198.18.0.0/15`, multicast/reservados (`>= 224`), multicast IPv6
  (`ff00::/8`) e IPv4 embebido en IPv6 en forma **hexadecimal** (`::ffff:7f00:1`).
- El override de loopback para tests exige además `NODE_ENV=test`.

### Corregido

- `Accept-Encoding: identity` para evitar cuerpos comprimidos que rompían el
  análisis (falsos negativos silenciosos).
- El informe usa la **URL final** tras las redirecciones.
- Se detecta certificado **caducado/inválido** aunque la descarga falle por el
  propio certificado.
- Las firmas de librerías aceptan versiones de **dos partes** (`x.y`).
- Un fichero de baseline ilegible degrada con aviso en vez de abortar.
- Las sondas activas avisan de fallos por stderr en vez de silenciarlos.

### Rendimiento y estabilidad

- **Keep-alive** en las conexiones (clave al crawlear el mismo host).
- El navegador headless se **reutiliza** para todo el lote (no uno por URL).
- **Deadline absoluto** por petición (anti goteo/slowloris).
- Tope de `--concurrency`, cota de memoria del crawler y opción `--delay` (cortesía).
- Avisos cuando se combinan `--headless`/`--active` con `--crawl`.

## [2.2.0] - 2026-06-08

Reescritura completa: de un script único a un analizador de seguridad web
modular, con arquitectura de reglas, múltiples formatos de salida e integración
continua que revisa seguridad y estructura en cada cambio.

### Añadido

- **Motor de reglas** (`src/`): cada comprobación es un módulo con `id` estable,
  severidad, categoría y referencia.
- **Parser HTML propio** (sin dependencias) para analizar etiquetas y atributos
  con más precisión que las expresiones regulares.
- **Cabeceras de seguridad**: CSP (con graduación de `unsafe-inline`/`unsafe-eval`,
  comodines, falta de `object-src`/`base-uri`), HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy y fingerprinting.
- **CORS** permisivo, **cookies** inseguras y prefijos `__Host-`/`__Secure-`,
  método **TRACE/TRACK**.
- **XSS**: manejadores `on*`, URIs `javascript:`, sumideros DOM, marcos embebidos,
  *mixed content*, formularios sin token anti-CSRF y posible open redirect.
- **Ofuscación**: `eval`/`eval(atob())`/`Function`/`fromCharCode` y escapes largos.
- **Librerías JS vulnerables** (estilo retire.js): jQuery, jQuery UI, AngularJS,
  Bootstrap, Lodash, Moment.js, Handlebars, Vue, Axios, DOMPurify, Underscore.
- **Inspección TLS**: protocolo obsoleto (TLS 1.0/1.1, SSLv3) y certificado
  caducado o próximo a caducar.
- **Modo activo** (`--active --authorized`): XSS reflejado, SSTI, SQLi
  error-based y open redirect.
- **Modo headless / DAST** (`--headless`, Playwright opcional): SPAs, violaciones
  de CSP en runtime y DOM-XSS.
- **Crawling** de mismo origen (`--crawl`, `--max-pages`) y **escaneo autenticado**
  (`--header`, `--cookie`).
- **Salidas**: consola, JSON (`--json`), SARIF (`--sarif`) y HTML (`--html`).
- **Modo baseline/diff** (`--baseline`) para reportar solo hallazgos nuevos.
- **Escaneo por lotes** (`--input`) y **concurrencia** (`--concurrency`).
- **Distribución**: `Dockerfile` y GitHub Action reutilizable (`action.yml`).
- **CI**: ESLint, typecheck (`tsc --checkJs`), 38 tests (unitarios + integración),
  `npm audit`, CodeQL y workflow de escaneo SARIF.

### Seguridad

- **Anti-SSRF**: bloquea direcciones internas/privadas y solo permite `http`/`https`.
- **Anti DNS-rebinding**: la conexión se fija a la IP ya validada.
- **Timeout** de petición y **límite de tamaño** de respuesta (anti-DoS).
- **Verificación TLS** explícita y redirecciones controladas.
- El modo activo exige autorización explícita (`--authorized`).

### Cambiado

- Migración de un único fichero a la estructura modular en `src/`.
- La detección de XSS pasó de expresiones regulares a análisis del DOM tokenizado.

[2.2.1]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.1
[2.2.0]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.0
