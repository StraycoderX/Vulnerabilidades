'use strict';

// Configuración central de la herramienta.
const REQUEST_TIMEOUT_MS = 10000; // Inactividad del socket
const MAX_TOTAL_MS = 30000; // Deadline absoluto por petición (anti goteo/slowloris)
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB: evita agotar memoria (DoS)
const MAX_REDIRECTS = 5; // Límite de saltos para evitar bucles de redirección
const MAX_CONCURRENCIA = 50; // Tope de escaneos en paralelo (evita auto-DoS)

// Niveles de severidad: orden para ordenar, etiqueta/color para la consola y
// nivel equivalente en SARIF para GitHub Code Scanning.
const SEVERIDAD = {
    alta: { orden: 3, etiqueta: 'ALTA', color: '\x1b[31m', sarif: 'error' },
    media: { orden: 2, etiqueta: 'MEDIA', color: '\x1b[33m', sarif: 'warning' },
    baja: { orden: 1, etiqueta: 'BAJA', color: '\x1b[36m', sarif: 'note' },
    info: { orden: 0, etiqueta: 'INFO', color: '\x1b[90m', sarif: 'note' },
};
const RESET = '\x1b[0m';

module.exports = {
    REQUEST_TIMEOUT_MS,
    MAX_TOTAL_MS,
    MAX_RESPONSE_BYTES,
    MAX_REDIRECTS,
    MAX_CONCURRENCIA,
    SEVERIDAD,
    RESET,
};
