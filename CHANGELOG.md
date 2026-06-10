# Changelog

Todas las novedades notables de este proyecto se documentan en este archivo.

El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y el proyecto sigue [Versionado Semántico](https://semver.org/lang/es/).

## [2.2.5] - 2026-06-09

### Añadido

- **Soporte de proxy** (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`) para entornos
  corporativos: HTTP por forma absoluta y HTTPS por túnel `CONNECT` con TLS
  extremo a extremo. A través de proxy no se fija la IP del destino (el anti
  DNS-rebinding no aplica), pero se mantienen la validación previa de host
  (anti-SSRF) y la verificación del certificado.

### Cambiado

- Las respuestas **4xx/5xx** ya **se analizan** (sus cabeceras de seguridad
  siguen siendo relevantes) en vez de abortar con `Respuesta HTTP 4xx`.

## [2.2.4] - 2026-06-09

### Corregido (crítico)

- **`Invalid IP address: undefined` al escanear sitios reales.** Desde Node 20,
  `autoSelectFamily` (Happy Eyeballs) llama al `lookup` fijado con `all: true`,
  que espera un array `[{address, family}]`. El `lookupFijo` (y la inspección
  TLS) solo devolvían el valor posicional, así que Node recibía una IP `undefined`
  y **fallaba todo escaneo de dominios reales** (dual-stack IPv4/IPv6). Ahora
  ambos `lookup` honran la opción `all`. Test de integración por nombre de host
  para evitar la regresión.

## [2.2.3] - 2026-06-09

Tercera pasada de revisión: dos vulnerabilidades de denegación de servicio (ReDoS)
contra la propia herramienta, encontradas midiendo el peor caso.

### Seguridad (corregido)

- **ReDoS en la regla de formularios**: la regex `[\s\S]*?</form>` era cuadrática;
  una respuesta hostil de ~1 MB con muchos `<form>` sin cerrar colgaba el escaneo
  decenas de segundos (con el límite de 5 MB, varios minutos). Ahora se cuentan
  los formularios con el DOM ya tokenizado (lineal). 56 s → 0,2 s.
- **ReDoS en las firmas de error SQL** (modo activo): los `.*` sin acotar entre
  dos tokens eran cuadráticos; se acotan a `.{0,200}`. 34 s → 0,2 s.

### Añadido

- Tests anti-DoS que ejercitan todas las reglas y las firmas SQL con HTML hostil
  grande, verificando que se mantienen lineales.

## [2.2.2] - 2026-06-08

Segunda pasada de revisión: falsos positivos y robustez de la salida.

### Corregido

- **Falso positivo de CSP**: una fuente concreta como `https://cdn.example.com`
  ya no se marca como "esquema permisivo" (solo `https:`/`http:` a secas o `*`).
- **Inyección en terminal**: se eliminan secuencias de control/ANSI del texto que
  proviene del sitio analizado antes de imprimirlo en consola.
- La versión del *tool* en la salida SARIF se toma de `package.json` (no fija).

### Cambiado

- La heurística pasiva de open redirect detecta también destinos sin codificar
  (`=https://…`, `=//…`) además de la forma codificada.

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

[2.2.5]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.5
[2.2.4]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.4
[2.2.3]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.3
[2.2.2]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.2
[2.2.1]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.1
[2.2.0]: https://github.com/StraycoderX/Vulnerabilidades/releases/tag/v2.2.0
