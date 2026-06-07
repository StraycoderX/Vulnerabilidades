'use strict';

const { SEVERIDAD } = require('./config');
const { reglas } = require('./rules');
const { validarObjetivo, descargar } = require('./net');
const { parsearHTML } = require('./parser');
const { inspeccionarTLS } = require('./tls');

// Ejecuta todas las reglas sobre el contexto y devuelve el reporte ordenado.
function analizar(ctx) {
    if (!ctx.dom) ctx.dom = parsearHTML(ctx.body || '');
    const hallazgos = reglas.flatMap((regla) => regla(ctx));
    hallazgos.sort((a, b) => SEVERIDAD[b.severidad].orden - SEVERIDAD[a.severidad].orden);
    return {
        url: ctx.url.href,
        statusCode: ctx.statusCode,
        totalHallazgos: hallazgos.length,
        hallazgos,
    };
}

// Descarga la URL (con controles anti-SSRF) y la analiza.
async function escanear(entrada) {
    const target = await validarObjetivo(entrada);
    const { statusCode, headers, body } = await descargar(target);
    // Para https, inspecciona el certificado y el protocolo TLS (no bloqueante).
    const tlsInfo = target.url.protocol === 'https:' ? await inspeccionarTLS(target).catch(() => null) : null;
    return analizar({ url: target.url, statusCode, headers, body, tls: tlsInfo });
}

// Código de salida ≠ 0 si hay hallazgos de severidad alta o media (útil en CI).
function exitCodePorHallazgos(reporte) {
    return reporte.hallazgos.some((f) => f.severidad === 'alta' || f.severidad === 'media') ? 1 : 0;
}

module.exports = { analizar, escanear, exitCodePorHallazgos };
