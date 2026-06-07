'use strict';

const { hallazgo, muestra } = require('./util');

const REF_XSS = 'https://owasp.org/www-community/attacks/xss/';

// Vectores de XSS y problemas de contenido en el HTML (heurística por regex;
// un parser daría más precisión, pendiente en el roadmap).
function analizarXSS(ctx) {
    const html = ctx.body;
    const hallazgos = [];

    const scripts = html.match(/<\s*script\b[^>]*>/gi) || [];
    if (scripts.length) {
        hallazgos.push(hallazgo({
            id: 'script-presente', severidad: 'info', categoria: 'xss',
            mensaje: `${scripts.length} etiqueta(s) <script> presentes`, referencia: REF_XSS,
            detalle: 'Revisa que los scripts inline usen nonce/hash y no reflejen entrada de usuario.',
        }));
    }

    const handlers = html.match(/\son[a-z]+\s*=\s*["'][^"']*["']/gi) || [];
    if (handlers.length) {
        hallazgos.push(hallazgo({
            id: 'evento-inline', severidad: 'media', categoria: 'xss',
            mensaje: `${handlers.length} manejador(es) de evento inline (on*=)`,
            detalle: muestra(handlers), referencia: REF_XSS,
        }));
    }

    const jsUris = html.match(/(?:href|src)\s*=\s*["']\s*javascript:[^"']*["']/gi) || [];
    if (jsUris.length) {
        hallazgos.push(hallazgo({
            id: 'javascript-uri', severidad: 'media', categoria: 'xss',
            mensaje: `${jsUris.length} URI javascript: detectada(s)`, detalle: muestra(jsUris), referencia: REF_XSS,
        }));
    }

    const domSinks = html.match(/\b(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b/gi) || [];
    if (domSinks.length) {
        hallazgos.push(hallazgo({
            id: 'dom-sink', severidad: 'baja', categoria: 'xss',
            mensaje: `Sumideros DOM peligrosos: ${[...new Set(domSinks.map((s) => s.toLowerCase()))].join(', ')}`,
            detalle: 'Si reciben entrada del usuario sin sanitizar pueden causar DOM-XSS.', referencia: REF_XSS,
        }));
    }

    const frames = html.match(/<\s*(iframe|object|embed)\b[^>]*>/gi) || [];
    if (frames.length) {
        hallazgos.push(hallazgo({
            id: 'marco-embebido', severidad: 'baja', categoria: 'contenido',
            mensaje: `${frames.length} marco(s) embebido(s) (iframe/object/embed)`,
        }));
    }

    if (ctx.url.protocol === 'https:') {
        const mixed = html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi) || [];
        if (mixed.length) {
            hallazgos.push(hallazgo({
                id: 'mixed-content', severidad: 'media', categoria: 'contenido',
                mensaje: `${mixed.length} recurso(s) cargados por HTTP en página HTTPS (mixed content)`,
                detalle: muestra(mixed),
            }));
        }
    }

    const forms = html.match(/<\s*form\b[^>]*>[\s\S]*?<\s*\/\s*form\s*>/gi) || [];
    const sinToken = forms.filter((f) => !/csrf|token|authenticity|_token|nonce/i.test(f));
    if (sinToken.length) {
        hallazgos.push(hallazgo({
            id: 'csrf-sin-token', severidad: 'baja', categoria: 'csrf',
            mensaje: `${sinToken.length} de ${forms.length} formulario(s) sin token anti-CSRF aparente`,
            detalle: 'Heurística: no se halló un campo con nombre csrf/token/nonce.',
        }));
    }

    // Posible open redirect: enlaces con parámetros de redirección hacia URL absoluta.
    const redirects = html.match(/[?&](?:url|next|redirect|return|dest|destination)=https?%3a/gi) || [];
    if (redirects.length) {
        hallazgos.push(hallazgo({
            id: 'open-redirect', severidad: 'info', categoria: 'redireccion',
            mensaje: `${redirects.length} enlace(s) con parámetro de redirección a URL absoluta`,
            detalle: 'Revisa que el destino esté validado contra una lista blanca (open redirect).',
        }));
    }

    return hallazgos;
}

module.exports = { analizarXSS };
