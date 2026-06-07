'use strict';

const { hallazgo } = require('./util');

// Metadatos por tipo de sonda activa.
const TIPOS = {
    xss: {
        id: 'xss-reflejado', severidad: 'alta', categoria: 'xss',
        mensaje: (p) => `Posible XSS reflejado en el parámetro "${p}"`,
        detalle: 'El marcador con caracteres especiales se reflejó sin escapar en la respuesta.',
        referencia: 'https://owasp.org/www-community/attacks/xss/',
    },
    ssti: {
        id: 'ssti', severidad: 'alta', categoria: 'inyeccion',
        mensaje: (p) => `Posible inyección de plantilla (SSTI) en el parámetro "${p}"`,
        detalle: 'Una expresión aritmética inyectada fue evaluada por el servidor.',
        referencia: 'https://owasp.org/www-community/attacks/Server-Side_Template_Injection',
    },
    sqli: {
        id: 'sqli-error', severidad: 'alta', categoria: 'inyeccion',
        mensaje: (p) => `Posible inyección SQL (error-based) en el parámetro "${p}"`,
        detalle: 'La respuesta contiene un mensaje de error de base de datos al inyectar comillas.',
        referencia: 'https://owasp.org/www-community/attacks/SQL_Injection',
    },
    'open-redirect': {
        id: 'open-redirect-activo', severidad: 'media', categoria: 'redireccion',
        mensaje: (p) => `Posible open redirect en el parámetro "${p}"`,
        detalle: 'El servidor redirige a un dominio externo controlado por el atacante.',
        referencia: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
    },
};

// Evalúa los resultados de las sondas activas (en ctx.active). Solo hay datos si
// el escaneo se lanzó con --active y --authorized.
function analizarActivo(ctx) {
    if (!Array.isArray(ctx.active)) return [];
    const hallazgos = [];
    for (const r of ctx.active) {
        if (!r || !r.detectado) continue;
        const meta = TIPOS[r.tipo];
        if (!meta) continue;
        hallazgos.push(hallazgo({
            id: meta.id,
            severidad: meta.severidad,
            categoria: meta.categoria,
            mensaje: meta.mensaje(r.parametro),
            detalle: meta.detalle,
            referencia: meta.referencia,
        }));
    }
    return hallazgos;
}

module.exports = { analizarActivo };
