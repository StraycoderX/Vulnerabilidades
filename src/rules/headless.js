'use strict';

const { hallazgo } = require('./util');

// Evalúa las observaciones del modo headless (en ctx.headless): violaciones de
// CSP en runtime y errores de JavaScript de la página renderizada.
function analizarHeadless(ctx) {
    const h = ctx.headless;
    if (!h) return [];
    const hallazgos = [];

    if (Array.isArray(h.violacionesCSP) && h.violacionesCSP.length) {
        hallazgos.push(hallazgo({
            id: 'csp-violacion-runtime', severidad: 'media', categoria: 'cabeceras',
            mensaje: `${h.violacionesCSP.length} violación(es) de CSP en tiempo de ejecución`,
            detalle: h.violacionesCSP[0].slice(0, 200),
            referencia: 'https://developer.mozilla.org/docs/Web/HTTP/CSP',
        }));
    }

    if (Array.isArray(h.erroresJS) && h.erroresJS.length) {
        hallazgos.push(hallazgo({
            id: 'error-js-runtime', severidad: 'info', categoria: 'contenido',
            mensaje: `${h.erroresJS.length} error(es) de JavaScript en la página`,
            detalle: h.erroresJS[0].slice(0, 200),
        }));
    }

    return hallazgos;
}

module.exports = { analizarHeadless };
