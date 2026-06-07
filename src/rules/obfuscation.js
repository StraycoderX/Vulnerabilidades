'use strict';

const { hallazgo } = require('./util');

// Heurística de código ofuscado / sospechoso, los patrones que se usan para
// esconder payloads y que una simple búsqueda de <script> no detecta.
function analizarOfuscacion(ctx) {
    const html = ctx.body;
    const hallazgos = [];
    const patrones = [
        [/\beval\s*\(\s*atob\s*\(/gi, 'eval(atob()) — patrón típico de payload oculto'],
        [/\beval\s*\(/gi, 'eval()'],
        [/\bFunction\s*\(\s*["'`]/gi, 'new Function(string)'],
        [/\batob\s*\(/gi, 'atob() (base64)'],
        [/\bunescape\s*\(/gi, 'unescape()'],
        [/String\.fromCharCode\s*\(/gi, 'String.fromCharCode()'],
    ];
    for (const [re, etiqueta] of patrones) {
        const n = (html.match(re) || []).length;
        if (n) {
            hallazgos.push(hallazgo({
                id: 'ofuscacion-' + etiqueta.replace(/[^a-z]/gi, '').toLowerCase().slice(0, 20),
                severidad: 'media', categoria: 'ofuscacion',
                mensaje: `Patrón sospechoso: ${etiqueta} ×${n}`,
            }));
        }
    }

    const hexes = html.match(/(?:\\x[0-9a-f]{2}){8,}/gi) || [];
    const unis = html.match(/(?:\\u[0-9a-f]{4}){6,}/gi) || [];
    if (hexes.length || unis.length) {
        hallazgos.push(hallazgo({
            id: 'ofuscacion-escapes', severidad: 'media', categoria: 'ofuscacion',
            mensaje: 'Cadenas con escapes hex/unicode largos',
            detalle: `\\xNN: ${hexes.length}, \\uNNNN: ${unis.length} (posible payload codificado).`,
        }));
    }

    return hallazgos;
}

module.exports = { analizarOfuscacion };
