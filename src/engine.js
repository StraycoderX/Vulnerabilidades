'use strict';

const { SEVERIDAD } = require('./config');
const { reglas } = require('./rules');
const { validarObjetivo, descargar } = require('./net');
const { parsearHTML } = require('./parser');
const { inspeccionarTLS } = require('./tls');
const { ejecutarSondasActivas } = require('./active');

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

    let descarga;
    try {
        descarga = await descargar(target, extra);
    } catch (err) {
        // Si el fallo es de certificado en https, inspecciona el TLS y reporta el
        // problema (p. ej. certificado caducado) en vez de abortar el escaneo.
        if (target.url.protocol === 'https:' && /cert|tls|ssl|altname|self.signed|expired|verif/i.test(err.message)) {
            const tlsInfo = await inspeccionarTLS(target).catch(() => null);
            if (tlsInfo && !tlsInfo.error) {
                const reporte = analizar({
                    url: target.url, statusCode: 0, headers: {}, body: '', tls: tlsInfo, active: null,
                });
                return { reporte, dom: parsearHTML(''), url: target.url };
            }
        }
        throw err;
    }

    const { statusCode, headers, body, url: urlFinal, tls } = descarga;

    // Sondas activas (XSS reflejado, SSTI, SQLi, open redirect): solo con
    // autorización explícita. Se prueban sobre la URL ORIGINAL (donde están los
    // parámetros que dio el usuario), aunque el informe use la URL final.
    let active = null;
    if (opciones.active && opciones.authorized) {
        active = await ejecutarSondasActivas(target, extra).catch(() => null);
    }

    const dom = parsearHTML(body || '');
    const reporte = analizar({ url: urlFinal, statusCode, headers, body, tls, active, dom });
    return { reporte, dom, url: urlFinal };
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
