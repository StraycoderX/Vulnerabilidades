'use strict';

const { URL } = require('url');
const { validarObjetivo, descargar } = require('./net');

// Marcador único e inofensivo: incluye caracteres de ruptura de contexto pero NO
// ejecuta nada. Si el servidor lo refleja sin escapar, indica XSS reflejado.
function nuevoMarcador() {
    const id = Math.random().toString(36).slice(2, 10);
    return `xZap${id}"'<>`;
}

// Detección pura: ¿aparece el marcador con sus caracteres especiales sin escapar?
function detectarReflejo(body, marcador) {
    if (!body) return false;
    // Si apareciese escapado (&lt; &quot;...) no cuenta como reflejo peligroso.
    return body.includes(marcador);
}

// Sonda de XSS reflejado sobre los parámetros de query de la URL. SOLO debe
// usarse con autorización explícita: envía una petición por parámetro.
// Devuelve [{ parametro, marcador, reflejado }].
async function probarXSSReflejado(target, extra = {}) {
    const resultados = [];
    const base = target.url;
    const params = [...base.searchParams.keys()];
    if (params.length === 0) return resultados;

    for (const p of params) {
        const marcador = nuevoMarcador();
        const u = new URL(base.href);
        u.searchParams.set(p, marcador);
        try {
            const t = await validarObjetivo(u.href);
            const { body } = await descargar(t, extra);
            resultados.push({ parametro: p, marcador, reflejado: detectarReflejo(body, marcador) });
        } catch {
            resultados.push({ parametro: p, marcador, reflejado: false, error: true });
        }
    }
    return resultados;
}

module.exports = { probarXSSReflejado, detectarReflejo, nuevoMarcador };
