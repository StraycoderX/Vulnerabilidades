'use strict';

const { URL } = require('url');
const { REQUEST_TIMEOUT_MS } = require('./config');
const { validarObjetivo } = require('./net');
const { analizar } = require('./engine');

// Modo DAST con navegador headless (Playwright como dependencia OPCIONAL).
// Renderiza la página (ejecuta su JS), por lo que analiza también SPAs y detecta
// violaciones de CSP en runtime y XSS basado en DOM. Si Playwright no está
// instalado, devuelve un error explicativo sin romper el resto de la herramienta.

function cargarPlaywright() {
    try {
        // Specifier dinámico: dependencia OPCIONAL, no resuelta en build/typecheck.
        const nombre = 'playwright';
        return require(nombre);
    } catch {
        return null;
    }
}

// Token y payload para la sonda de DOM-XSS (solo se usa con autorización).
function nuevoTokenDOM() {
    return 'domxss' + Math.random().toString(36).slice(2, 9);
}

async function escanearHeadless(entrada, opciones = {}, deps = {}) {
    const playwright = deps.playwright || cargarPlaywright();
    if (!playwright) {
        return {
            error:
                'Playwright no está instalado. Para usar --headless ejecuta:\n' +
                '  npm install -D playwright && npx playwright install chromium',
        };
    }

    const target = await validarObjetivo(entrada); // mantiene el control anti-SSRF
    const navegador = await playwright.chromium.launch({ args: ['--no-sandbox'] });
    try {
        const extraHTTPHeaders = { ...(opciones.headers || {}) };
        if (opciones.cookie) extraHTTPHeaders['Cookie'] = opciones.cookie;
        const contexto = await navegador.newContext({ extraHTTPHeaders, ignoreHTTPSErrors: false });
        const page = await contexto.newPage();

        const violacionesCSP = [];
        const erroresJS = [];
        let tokenDialogo = null;

        page.on('console', (m) => {
            if (/content security policy/i.test(m.text())) violacionesCSP.push(m.text());
        });
        page.on('pageerror', (e) => erroresJS.push(String(e && e.message ? e.message : e)));
        page.on('dialog', async (d) => {
            tokenDialogo = d.message();
            await d.dismiss().catch(() => {});
        });

        const resp = await page.goto(target.url.href, {
            waitUntil: 'networkidle',
            timeout: REQUEST_TIMEOUT_MS,
        });
        const html = await page.content();

        // Sonda de DOM-XSS: solo con autorización explícita.
        const active = [];
        if (opciones.active && opciones.authorized) {
            const params = [...target.url.searchParams.keys()];
            for (const p of params) {
                const token = nuevoTokenDOM();
                const u = new URL(target.url.href);
                u.searchParams.set(p, `"><img src=x onerror=alert('${token}')>`);
                tokenDialogo = null;
                try {
                    const t = await validarObjetivo(u.href);
                    await page.goto(t.url.href, { waitUntil: 'networkidle', timeout: REQUEST_TIMEOUT_MS });
                } catch {
                    /* ignora fallos de navegación de la sonda */
                }
                active.push({ tipo: 'dom-xss', parametro: p, detectado: tokenDialogo === token });
            }
        }

        const ctx = {
            url: target.url,
            statusCode: resp ? resp.status() : 0,
            headers: resp ? resp.headers() : {},
            body: html,
            tls: null,
            active,
            headless: { violacionesCSP, erroresJS },
        };
        return { reporte: analizar(ctx) };
    } finally {
        await navegador.close().catch(() => {});
    }
}

module.exports = { escanearHeadless };
