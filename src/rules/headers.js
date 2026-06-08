'use strict';

const { hallazgo, normalizarCabeceras } = require('./util');

const REF_OWASP = 'https://owasp.org/www-project-secure-headers/';

// Graduación de la CSP: una CSP presente pero permisiva ofrece poca protección.
function graduarCSP(csp) {
    const hallazgos = [];
    const v = csp.toLowerCase();

    if (v.includes("'unsafe-inline'")) {
        hallazgos.push(hallazgo({
            id: 'csp-unsafe-inline', severidad: 'media', categoria: 'cabeceras',
            mensaje: "CSP permite 'unsafe-inline'", referencia: REF_OWASP,
            detalle: 'Anula gran parte de la protección de la CSP contra XSS.',
        }));
    }
    if (v.includes("'unsafe-eval'")) {
        hallazgos.push(hallazgo({
            id: 'csp-unsafe-eval', severidad: 'media', categoria: 'cabeceras',
            mensaje: "CSP permite 'unsafe-eval'", referencia: REF_OWASP,
            detalle: 'Habilita eval()/new Function(), vectores de inyección.',
        }));
    }
    // Comodín de origen (*) o esquema permisivo como fuente (https: a secas),
    // pero NO una fuente concreta como https://cdn.example.com.
    if (/(?:default-src|script-src)[^;]*(\*|https?:(?!\/\/))(\s|;|$)/.test(v)) {
        hallazgos.push(hallazgo({
            id: 'csp-wildcard', severidad: 'media', categoria: 'cabeceras',
            mensaje: 'CSP con origen comodín (*) o esquema permisivo en las fuentes de script',
            referencia: REF_OWASP,
        }));
    }
    if (!v.includes('object-src')) {
        hallazgos.push(hallazgo({
            id: 'csp-no-object-src', severidad: 'baja', categoria: 'cabeceras',
            mensaje: "CSP sin object-src 'none'", referencia: REF_OWASP,
            detalle: 'Permite plugins/objetos embebidos potencialmente peligrosos.',
        }));
    }
    if (!v.includes('base-uri')) {
        hallazgos.push(hallazgo({
            id: 'csp-no-base-uri', severidad: 'baja', categoria: 'cabeceras',
            mensaje: 'CSP sin base-uri', referencia: REF_OWASP,
            detalle: 'Sin base-uri, un atacante podría reescribir URLs relativas.',
        }));
    }
    return hallazgos;
}

// Analiza una cookie individual y devuelve hallazgos por atributos faltantes.
function analizarCookie(cookie, esHttps) {
    const hallazgos = [];
    const nombre = cookie.split('=')[0].trim();
    const faltan = [];
    if (esHttps && !/;\s*secure/i.test(cookie)) faltan.push('Secure');
    if (!/;\s*httponly/i.test(cookie)) faltan.push('HttpOnly');
    if (!/;\s*samesite/i.test(cookie)) faltan.push('SameSite');
    if (faltan.length) {
        hallazgos.push(hallazgo({
            id: 'cookie-insegura', severidad: 'media', categoria: 'cookies',
            mensaje: `Cookie "${nombre}" sin atributos: ${faltan.join(', ')}`,
        }));
    }
    if (/;\s*samesite\s*=\s*none/i.test(cookie) && !/;\s*secure/i.test(cookie)) {
        hallazgos.push(hallazgo({
            id: 'cookie-samesite-none-sin-secure', severidad: 'media', categoria: 'cookies',
            mensaje: `Cookie "${nombre}" con SameSite=None pero sin Secure`,
        }));
    }
    // Prefijos especiales: __Host- y __Secure- imponen requisitos.
    if (/^__secure-/i.test(nombre) && !/;\s*secure/i.test(cookie)) {
        hallazgos.push(hallazgo({
            id: 'cookie-prefijo-secure', severidad: 'baja', categoria: 'cookies',
            mensaje: `Cookie "${nombre}" usa prefijo __Secure- sin atributo Secure`,
        }));
    }
    if (/^__host-/i.test(nombre)) {
        if (!/;\s*secure/i.test(cookie) || /;\s*domain=/i.test(cookie) || !/;\s*path=\/(\s|;|$)/i.test(cookie)) {
            hallazgos.push(hallazgo({
                id: 'cookie-prefijo-host', severidad: 'baja', categoria: 'cookies',
                mensaje: `Cookie "${nombre}" con prefijo __Host- no cumple Secure + Path=/ + sin Domain`,
            }));
        }
    }
    return hallazgos;
}

// Regla principal de cabeceras de seguridad.
function analizarCabeceras(ctx) {
    const h = normalizarCabeceras(ctx.headers);
    const hallazgos = [];
    const esHttps = ctx.url.protocol === 'https:';

    const csp = h['content-security-policy'];
    if (!csp) {
        hallazgos.push(hallazgo({
            id: 'csp-ausente', severidad: 'media', categoria: 'cabeceras',
            mensaje: 'Falta Content-Security-Policy (CSP)', referencia: REF_OWASP,
            detalle: 'CSP es la principal mitigación contra XSS e inyección de recursos.',
        }));
    } else {
        hallazgos.push(...graduarCSP(csp));
    }

    if (esHttps && !h['strict-transport-security']) {
        hallazgos.push(hallazgo({
            id: 'hsts-ausente', severidad: 'media', categoria: 'cabeceras',
            mensaje: 'Falta Strict-Transport-Security (HSTS)', referencia: REF_OWASP,
            detalle: 'Permite ataques de downgrade/MITM en la primera conexión.',
        }));
    }
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp || '')) {
        hallazgos.push(hallazgo({
            id: 'clickjacking', severidad: 'baja', categoria: 'cabeceras',
            mensaje: 'Falta protección anti-clickjacking (X-Frame-Options / frame-ancestors)',
            referencia: REF_OWASP,
        }));
    }
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
        hallazgos.push(hallazgo({
            id: 'nosniff-ausente', severidad: 'baja', categoria: 'cabeceras',
            mensaje: 'Falta X-Content-Type-Options: nosniff', referencia: REF_OWASP,
        }));
    }
    if (!h['referrer-policy']) {
        hallazgos.push(hallazgo({ id: 'referrer-policy-ausente', severidad: 'info', categoria: 'cabeceras', mensaje: 'Falta Referrer-Policy' }));
    }
    if (!h['permissions-policy']) {
        hallazgos.push(hallazgo({ id: 'permissions-policy-ausente', severidad: 'info', categoria: 'cabeceras', mensaje: 'Falta Permissions-Policy' }));
    }
    if (h['server'] || h['x-powered-by']) {
        hallazgos.push(hallazgo({
            id: 'fingerprinting', severidad: 'info', categoria: 'fingerprinting',
            mensaje: 'Expone tecnología del servidor',
            detalle: [h['server'] && `Server: ${h['server']}`, h['x-powered-by'] && `X-Powered-By: ${h['x-powered-by']}`]
                .filter(Boolean).join(' | '),
        }));
    }

    // CORS permisivo.
    const acao = h['access-control-allow-origin'];
    const acac = (h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (acao === '*' && acac) {
        hallazgos.push(hallazgo({
            id: 'cors-comodin-credenciales', severidad: 'alta', categoria: 'cors',
            mensaje: 'CORS permite cualquier origen (*) junto con credenciales',
            detalle: 'Combinación peligrosa: expone datos autenticados a cualquier sitio.',
        }));
    } else if (acao === '*') {
        hallazgos.push(hallazgo({
            id: 'cors-comodin', severidad: 'baja', categoria: 'cors',
            mensaje: 'CORS permite cualquier origen (Access-Control-Allow-Origin: *)',
        }));
    }

    // Métodos peligrosos (si el servidor expone el encabezado Allow).
    const allow = (h['allow'] || '').toUpperCase();
    if (/\bTRACE\b|\bTRACK\b/.test(allow)) {
        hallazgos.push(hallazgo({
            id: 'metodo-trace', severidad: 'media', categoria: 'metodos',
            mensaje: 'El servidor anuncia el método TRACE/TRACK (riesgo de Cross-Site Tracing)',
            detalle: `Allow: ${allow}`,
        }));
    }

    // Cookies.
    for (const cookie of [].concat(h['set-cookie'] || [])) {
        hallazgos.push(...analizarCookie(cookie, esHttps));
    }

    return hallazgos;
}

module.exports = { analizarCabeceras, graduarCSP, analizarCookie };
