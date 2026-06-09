'use strict';

const { hallazgo, muestra } = require('./util');
const { parsearHTML } = require('../parser');

const REF_XSS = 'https://owasp.org/www-community/attacks/xss/';

// Vectores de XSS y problemas de contenido, usando el HTML ya tokenizado para
// inspeccionar etiquetas y atributos con más precisión que una regex suelta.
function analizarXSS(ctx) {
    const html = ctx.body;
    const dom = ctx.dom || parsearHTML(html || '');
    const hallazgos = [];
    const esHttps = ctx.url.protocol === 'https:';

    const scripts = dom.elementos.filter((e) => e.tag === 'script');
    if (scripts.length) {
        hallazgos.push(hallazgo({
            id: 'script-presente', severidad: 'info', categoria: 'xss',
            mensaje: `${scripts.length} etiqueta(s) <script> presentes`, referencia: REF_XSS,
            detalle: 'Revisa que los scripts inline usen nonce/hash y no reflejen entrada de usuario.',
        }));
    }

    // Manejadores de evento inline (atributos on*).
    const handlers = [];
    const jsUris = [];
    const mixed = [];
    for (const el of dom.elementos) {
        for (const [nombre, valor] of Object.entries(el.attrs)) {
            if (/^on[a-z]+$/.test(nombre) && valor) handlers.push(`<${el.tag} ${nombre}="${valor}">`);
            if ((nombre === 'href' || nombre === 'src') && /^\s*javascript:/i.test(valor)) {
                jsUris.push(`<${el.tag} ${nombre}="${valor}">`);
            }
            if (esHttps && (nombre === 'src' || nombre === 'href') && /^http:\/\//i.test(valor)) {
                mixed.push(`<${el.tag} ${nombre}="${valor}">`);
            }
        }
    }

    if (handlers.length) {
        hallazgos.push(hallazgo({
            id: 'evento-inline', severidad: 'media', categoria: 'xss',
            mensaje: `${handlers.length} manejador(es) de evento inline (on*=)`,
            detalle: muestra(handlers), referencia: REF_XSS,
        }));
    }
    if (jsUris.length) {
        hallazgos.push(hallazgo({
            id: 'javascript-uri', severidad: 'media', categoria: 'xss',
            mensaje: `${jsUris.length} URI javascript: detectada(s)`, detalle: muestra(jsUris), referencia: REF_XSS,
        }));
    }
    if (mixed.length) {
        hallazgos.push(hallazgo({
            id: 'mixed-content', severidad: 'media', categoria: 'contenido',
            mensaje: `${mixed.length} recurso(s) cargados por HTTP en página HTTPS (mixed content)`,
            detalle: muestra(mixed),
        }));
    }

    const frames = dom.elementos.filter((e) => ['iframe', 'object', 'embed'].includes(e.tag));
    if (frames.length) {
        hallazgos.push(hallazgo({
            id: 'marco-embebido', severidad: 'baja', categoria: 'contenido',
            mensaje: `${frames.length} marco(s) embebido(s) (iframe/object/embed)`,
        }));
    }

    // Sumideros DOM peligrosos: se buscan en el contenido de los scripts.
    const codigoJS = scripts.map((s) => s.contenido).join('\n');
    const domSinks = codigoJS.match(/\b(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b/gi) || [];
    if (domSinks.length) {
        hallazgos.push(hallazgo({
            id: 'dom-sink', severidad: 'baja', categoria: 'xss',
            mensaje: `Sumideros DOM peligrosos: ${[...new Set(domSinks.map((s) => s.toLowerCase()))].join(', ')}`,
            detalle: 'Si reciben entrada del usuario sin sanitizar pueden causar DOM-XSS.', referencia: REF_XSS,
        }));
    }

    // Formularios sin token anti-CSRF. Se cuentan los <form> con el DOM ya
    // tokenizado (lineal) y se comprueba si hay algún campo anti-CSRF en la
    // página con una regex lineal. Evita el escaneo cuadrático de [\s\S]*?</form>.
    const forms = dom.elementos.filter((e) => e.tag === 'form').length;
    if (forms > 0) {
        const hayToken = /(?:name|id)\s*=\s*["']?[^"'>\s]*(?:csrf|token|authenticity|_token|nonce)/i.test(html || '');
        if (!hayToken) {
            hallazgos.push(hallazgo({
                id: 'csrf-sin-token', severidad: 'baja', categoria: 'csrf',
                mensaje: `${forms} formulario(s) y ningún campo anti-CSRF aparente en la página`,
                detalle: 'Heurística: no se halló un campo con nombre csrf/token/authenticity/nonce.',
            }));
        }
    }

    // Posible open redirect: parámetro de redirección hacia URL absoluta,
    // tanto codificada (https%3a) como sin codificar (https://) o sin esquema (//).
    const redirects =
        (html || '').match(/[?&](?:url|next|redirect|redir|return|returnurl|dest|destination|continue|goto|to)=(?:https?(?::|%3a)|%2f%2f|\/\/)/gi) || [];
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
