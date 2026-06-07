'use strict';

const { SEVERIDAD } = require('./config');
const { reglas } = require('./rules');
const { validarObjetivo, descargar } = require('./net');
const { parsearHTML } = require('./parser');
const { inspeccionarTLS } = require('./tls');
const { probarXSSReflejado } = require('./active');

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

// Construye las cabeceras de petición a partir de opciones (escaneo autenticado).
function construirCabeceras(opciones) {
    const headers = { ...(opciones.headers || {}) };
    if (opciones.cookie) headers['Cookie'] = opciones.cookie;
    return headers;
}

// Descarga la URL (con controles anti-SSRF) y la analiza. Devuelve también el DOM
// (para el crawler) en la propiedad `dom`.
async function escanearDetallado(entrada, opciones = {}) {
    const target = await validarObjetivo(entrada);
    const extra = { headers: construirCabeceras(opciones) };
    const { statusCode, headers, body } = await descargar(target, extra);

    const tlsInfo = target.url.protocol === 'https:' ? await inspeccionarTLS(target).catch(() => null) : null;

    // Modo activo (XSS reflejado): solo con autorización explícita.
    let active = null;
    if (opciones.active && opciones.authorized) {
        active = await probarXSSReflejado(target, extra).catch(() => null);
    }

    const dom = parsearHTML(body || '');
    const reporte = analizar({ url: target.url, statusCode, headers, body, tls: tlsInfo, active, dom });
    return { reporte, dom, url: target.url };
}

// Variante simple: solo el reporte.
async function escanear(entrada, opciones = {}) {
    return (await escanearDetallado(entrada, opciones)).reporte;
}

// Código de salida ≠ 0 si hay hallazgos de severidad alta o media (útil en CI).
function exitCodePorHallazgos(reporte) {
    return reporte.hallazgos.some((f) => f.severidad === 'alta' || f.severidad === 'media') ? 1 : 0;
}

module.exports = { analizar, escanear, escanearDetallado, exitCodePorHallazgos };
