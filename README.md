# Analizador de Vulnerabilidades Web

Herramienta de consola en Node.js (sin dependencias) que descarga una página y
emite un reporte de seguridad con **niveles de severidad**: revisa cabeceras de
seguridad, vectores de XSS y patrones de código ofuscado.

> ⚠️ Es una herramienta de apoyo basada en heurísticas, no un escáner
> exhaustivo. Úsala solo sobre sitios para los que tengas autorización.

## Uso

```bash
node index.js                     # Modo interactivo (pregunta URLs)
node index.js <url> [<url>...]    # Analiza una o varias URLs y termina
node index.js --json <url>        # Salida en formato JSON (para CI)
node index.js --help             # Ayuda
npm test                          # Ejecuta los tests (node --test)
```

En modo interactivo, escribe `salir` (o pulsa Ctrl+C) para terminar.

**Código de salida (modo CLI):** `0` sin hallazgos altos/medios · `1` con
ellos · `2` si hubo errores. Útil para fallar un pipeline de CI.

## Qué analiza

- **Cabeceras de seguridad:** CSP, HSTS, X-Frame-Options / `frame-ancestors`,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, exposición de
  tecnología (`Server`/`X-Powered-By`) y cookies sin `Secure`/`HttpOnly`/`SameSite`.
- **Vectores de XSS:** manejadores de evento inline (`on*=`), URIs `javascript:`,
  sumideros DOM (`innerHTML`, `document.write`…), marcos embebidos, *mixed
  content* (recursos HTTP en página HTTPS) y formularios sin token anti-CSRF aparente.
- **Ofuscación:** `eval()`, `eval(atob())`, `new Function(string)`, `unescape()`,
  `String.fromCharCode()` y cadenas con escapes `\xNN`/`\uNNNN` largos.

## Controles de seguridad de la propia herramienta

- **Anti-SSRF:** resuelve el host y bloquea direcciones internas/privadas
  (loopback, link-local/metadata cloud `169.254.169.254`, rangos RFC 1918,
  IPv6 ULA/link-local e IPv4 embebido en IPv6 `::ffff:`). Solo `http`/`https`.
- **Timeout** de petición (10 s) y **límite de tamaño** de respuesta (5 MB, anti-DoS).
- **Verificación TLS** explícita y **redirecciones** controladas (máx. 5,
  revalidando anti-SSRF en cada salto).

## Próximas mejoras sugeridas

- Parser HTML real (`parse5`/`cheerio`) para reducir falsos positivos de las
  heurísticas regex.
- Escaneo por lotes con concurrencia limitada desde un fichero de URLs.
- Fijar la conexión a la IP ya validada (evitar DNS rebinding).
- ESLint + Prettier y workflow de CI en GitHub Actions.
