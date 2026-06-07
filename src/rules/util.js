'use strict';

// Crea un hallazgo con un `id` estable (se usa como ruleId en SARIF).
function hallazgo({ id, severidad, categoria, mensaje, detalle, referencia }) {
    return {
        id,
        severidad,
        categoria,
        mensaje,
        detalle: detalle || null,
        referencia: referencia || null,
    };
}

// Normaliza las cabeceras a minúsculas para búsquedas insensibles a mayúsculas.
function normalizarCabeceras(headers) {
    const h = {};
    for (const k of Object.keys(headers || {})) h[k.toLowerCase()] = headers[k];
    return h;
}

// Devuelve una muestra recortada de coincidencias para el detalle del hallazgo.
function muestra(arr, n = 3) {
    return arr.slice(0, n).map((s) => String(s).trim().slice(0, 120)).join(' || ');
}

module.exports = { hallazgo, normalizarCabeceras, muestra };
