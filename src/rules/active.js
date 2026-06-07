'use strict';

const { hallazgo } = require('./util');

const REF_XSS = 'https://owasp.org/www-community/attacks/xss/';

// Evalúa los resultados de la sonda activa de XSS reflejado (en ctx.active).
// Solo hay datos si el escaneo se lanzó con modo activo y autorización.
function analizarActivo(ctx) {
    if (!Array.isArray(ctx.active)) return [];
    const hallazgos = [];
    for (const r of ctx.active) {
        if (r.reflejado) {
            hallazgos.push(hallazgo({
                id: 'xss-reflejado',
                severidad: 'alta',
                categoria: 'xss',
                mensaje: `Posible XSS reflejado en el parámetro "${r.parametro}"`,
                detalle: 'El marcador con caracteres especiales se reflejó sin escapar en la respuesta.',
                referencia: REF_XSS,
            }));
        }
    }
    return hallazgos;
}

module.exports = { analizarActivo };
