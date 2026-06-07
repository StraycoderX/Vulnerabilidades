# Analizador de Vulnerabilidades Web

Herramienta de consola en Node.js que descarga una página y localiza las
etiquetas `<script>` presentes en el HTML para revisión manual.

> ⚠️ La presencia de `<script>` **no** implica una vulnerabilidad de XSS por sí
> sola. Esta herramienta es un punto de partida, no un escáner de XSS completo.

## Uso

```bash
node index.js
```

Introduce una URL (`http://` o `https://`) cuando se solicite. Escribe `salir`
(o pulsa Ctrl+C) para terminar.

## Controles de seguridad

- **Anti-SSRF**: resuelve el host y bloquea direcciones internas/privadas
  (loopback, link-local/metadata cloud `169.254.169.254`, rangos RFC 1918 e
  IPv6 ULA/link-local). Solo se permiten esquemas `http`/`https`.
- **Timeout** de petición (10 s) para evitar conexiones colgadas.
- **Límite de tamaño** de respuesta (5 MB) para evitar agotar memoria (DoS).
- **Verificación TLS** explícita (`rejectUnauthorized: true`).
- **Redirecciones** controladas (máx. 5, revalidando anti-SSRF en cada salto).

## Próximas mejoras sugeridas

- Sustituir la detección por regex por un parser HTML real (`parse5`/`cheerio`)
  y detectar vectores reales: handlers `on*`, `javascript:`, `innerHTML`,
  `document.write`, etc.
- Analizar cabeceras de seguridad (CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options).
- Heurística de detección de código ofuscado (`eval`, `atob`, `Function()`,
  `\xNN`, `fromCharCode`).
- Sistema de severidad y salida en JSON para integración en CI.
- Modo CLI no interactivo: `node index.js <url>`.
