# Modelo de amenazas

Este documento describe las fronteras de confianza de la herramienta, los abusos
plausibles y las salvaguardas que los mitigan. Es una herramienta de **doble uso**
(seguridad ofensiva/defensiva), por lo que el diseño asume entradas hostiles.

## Activos a proteger

- **La máquina y la red de quien ejecuta la herramienta** (que no se use como
  pivote hacia infraestructura interna).
- **Las credenciales** que el usuario pasa para escaneo autenticado (`--header`,
  `--cookie`).
- **La integridad del proceso** (que una respuesta hostil no lo cuelgue ni lo
  haga consumir memoria sin límite).
- **El objetivo legítimo** (que la herramienta no ataque sin autorización).

## Fronteras de confianza

1. **Entrada del usuario** (URL, flags, ficheros) — semi-confiable.
2. **Respuesta del servidor analizado** (HTML, cabeceras, certificados,
   redirecciones) — **no confiable**. Es el principal vector de ataque.
3. **Dependencias** — el núcleo tiene **cero** dependencias de ejecución;
   Playwright es opcional. Las GitHub Actions se actualizan vía Dependabot.

## Amenazas y mitigaciones

| Amenaza | Mitigación |
|---|---|
| **SSRF** (alcanzar metadatos de cloud o servicios internos) | `validarObjetivo` resuelve el host y bloquea rangos privados/reservados (RFC 1918, loopback, link-local, CGNAT, multicast, IPv4-mapped en IPv6). Solo `http`/`https`. |
| **DNS rebinding** (resolver a IP distinta entre validación y conexión) | La conexión se fija a la IP ya validada (`lookupFijo`). |
| **SSRF vía redirección** | Cada `Location` se revalida con `validarObjetivo` antes de seguirla. |
| **Fuga de credenciales** a otro origen tras redirección | Se eliminan `Cookie`/`Authorization` si el destino cambia de origen. |
| **DoS sobre la propia herramienta** (respuesta infinita/lenta) | Límite de tamaño (5 MB), timeout de inactividad y *deadline* absoluto por petición. |
| **Auto-DoS** (demasiada concurrencia) | Tope de `--concurrency`; cota de memoria y `--delay` en el crawler. |
| **Inyección de terminal** (secuencias ANSI en el contenido analizado) | `limpiarControl` elimina caracteres de control antes de imprimir en consola; la salida HTML escapa el contenido. |
| **ReDoS / cuelgue del parser** | Parser O(n) sin retroceso catastrófico; cubierto por fuzzing. |
| **Uso del modo activo como arma** | El modo activo (`--active`) exige `--authorized`; las sondas son inofensivas (marcadores, no payloads destructivos). |
| **0-day del navegador headless** | Playwright es opcional y aislado; se recomienda ejecutarlo en un contenedor. |

## Fuera de alcance

- No protege frente a un usuario local malicioso que ya controla el proceso o el
  entorno (p. ej. variables de entorno).
- No garantiza detección exhaustiva: es una herramienta de heurísticas.
- La excepción de loopback para tests exige `NODE_ENV=test` **y** una variable
  explícita; no debe activarse en producción.

## Riesgos residuales

- El modo headless con `--no-sandbox` amplía el impacto de un fallo del navegador
  (compromiso aceptado para compatibilidad con contenedores).
- Las heurísticas pueden producir falsos positivos/negativos; trátese el informe
  como punto de partida, no como veredicto.

## Reporte de vulnerabilidades

Consulta [SECURITY.md](SECURITY.md).
