'use strict';

const { URL } = require('url');
const { validarObjetivo, descargar } = require('./net');

// --- Marcadores y detección (funciones puras, testeables) ------------------

// Marcador inofensivo con caracteres de ruptura de contexto (no ejecuta nada).
function nuevoMarcador() {
    const id = Math.random().toString(36).slice(2, 10);
    return `xZap${id}"'<>`;
}

// ¿El marcador aparece sin escapar en la respuesta?
function detectarReflejo(body, marcador) {
    return !!body && body.includes(marcador);
}

// Payload SSTI que, si la plantilla lo evalúa, produce s7·10001·s7 = "s710001s7".
const SSTI_PAYLOAD = 's7{{73*137}}s7 s7${73*137}s7 s7<%=73*137%>s7';
const SSTI_ESPERADO = 's710001s7';

// Firmas de error SQL típicas en la respuesta.
const FIRMAS_SQL = [
    /SQL syntax.*MySQL/i, /Warning.*\bmysqli?_/i, /valid MySQL result/i,
    /PostgreSQL.*ERROR/i, /Npgsql\./i, /ORA-\d{5}/i, /SQLite\/JDBCDriver/i,
    /SQLiteException/i, /Microsoft OLE DB Provider for ODBC Drivers/i,
    /Unclosed quotation mark after the character string/i, /quoted string not properly terminated/i,
];

function detectarErrorSQL(body) {
    return !!body && FIRMAS_SQL.some((re) => re.test(body));
}

const PARAMS_REDIRECT = /^(?:url|next|redirect|redir|return|returnurl|dest|destination|continue|goto|to)$/i;
const CANARIO_REDIRECT = 'https://redirect-canary.example/';

// --- Sondas (envían peticiones; SOLO con autorización) ---------------------

async function pedirConParametro(target, parametro, valor, extra) {
    const u = new URL(target.url.href);
    u.searchParams.set(parametro, valor);
    const t = await validarObjetivo(u.href);
    return descargar(t, extra);
}

async function sondaXSS(target, p, extra) {
    const marcador = nuevoMarcador();
    try {
        const { body } = await pedirConParametro(target, p, marcador, extra);
        return { tipo: 'xss', parametro: p, detectado: detectarReflejo(body, marcador) };
    } catch {
        return null;
    }
}

async function sondaSSTI(target, p, extra) {
    try {
        const { body } = await pedirConParametro(target, p, SSTI_PAYLOAD, extra);
        return { tipo: 'ssti', parametro: p, detectado: !!body && body.includes(SSTI_ESPERADO) };
    } catch {
        return null;
    }
}

async function sondaSQLi(target, p, extra) {
    try {
        const { body } = await pedirConParametro(target, p, "1'\"", extra);
        return { tipo: 'sqli', parametro: p, detectado: detectarErrorSQL(body) };
    } catch {
        return null;
    }
}

async function sondaOpenRedirect(target, p, extra) {
    try {
        const { statusCode, headers } = await pedirConParametro(target, p, CANARIO_REDIRECT, {
            ...extra,
            noFollow: true,
        });
        const loc = headers && headers.location ? String(headers.location) : '';
        const detectado = statusCode >= 300 && statusCode < 400 && loc.includes('redirect-canary.example');
        return { tipo: 'open-redirect', parametro: p, detectado };
    } catch {
        return null;
    }
}

// Ejecuta todas las sondas activas sobre los parámetros de query de la URL.
// Devuelve [{ tipo, parametro, detectado }].
async function ejecutarSondasActivas(target, extra = {}) {
    const params = [...target.url.searchParams.keys()];
    const resultados = [];
    for (const p of params) {
        resultados.push(await sondaXSS(target, p, extra));
        resultados.push(await sondaSSTI(target, p, extra));
        resultados.push(await sondaSQLi(target, p, extra));
        if (PARAMS_REDIRECT.test(p)) resultados.push(await sondaOpenRedirect(target, p, extra));
    }
    return resultados.filter(Boolean);
}

module.exports = {
    ejecutarSondasActivas,
    detectarReflejo,
    detectarErrorSQL,
    nuevoMarcador,
};
