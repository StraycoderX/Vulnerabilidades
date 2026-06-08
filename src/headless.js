'use strict';

const { URL } = require('url');
const { REQUEST_TIMEOUT_MS } = require('./config');
const { validarObjetivo } = require('./net');
const { analizar } = require('./engine');
const { mapearConcurrencia } = require('./pool');

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

function errorPlaywright() {
    return {
        error:
            'Playwright no está instalado. Para usar --headless ejecuta:\n' +
            '  npm install -D playwright && npx playwright install chromium',
    };
}

function nuevoTokenDOM() {
    return 'domxss' + Math.random().toString(36).slice(2, 9);
}

// Analiza una URL en un contexto nuevo del navegador dado. Cierra el contexto
// (no el navegador), para poder reutilizar el navegador en lotes.
async function escanearPagina(navegador, entrada, opciones = {}) {
    const target = await validarObjetivo(entrada); // mantiene el control anti-SSRF
    const extraHTTPHeaders = { ...(opciones.headers || {}) };
    if (opciones.cookie) extraHTTPHeaders['Cookie'] = opciones.cookie;
    const contexto = await navegador.newContext({ extraHTTPHeaders, ignoreHTTPSErrors: false });
    try {
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

        const resp = await page.goto(target.url.href, { waitUntil: 'networkidle', timeout: REQUEST_TIMEOUT_MS });
        const html = await page.content();

        // Sonda de DOM-XSS: solo con autorización explícita.
        const active = [];
        if (opciones.active && opciones.authorized) {
            for (const p of target.url.searchParams.keys()) {
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
        await contexto.close().catch(() => {});
    }
}

// Escaneo headless de UNA URL (lanza y cierra su propio navegador salvo que se
// inyecte uno en deps.browser, p. ej. en tests).
async function escanearHeadless(entrada, opciones = {}, deps = {}) {
    const playwright = deps.playwright || cargarPlaywright();
    if (!playwright && !deps.browser) return errorPlaywright();

    const propio = !deps.browser;
    const navegador = deps.browser || (await playwright.chromium.launch({ args: ['--no-sandbox'] }));
    try {
        return await escanearPagina(navegador, entrada, opciones);
    } finally {
        if (propio) await navegador.close().catch(() => {});
    }
}

// Escaneo headless de un LOTE de URLs reutilizando un único navegador (mucho más
// eficiente que arrancar uno por URL).
async function escanearHeadlessLote(urls, opciones = {}, deps = {}) {
    const playwright = deps.playwright || cargarPlaywright();
    if (!playwright && !deps.browser) return urls.map((u) => ({ url: u, ...errorPlaywright() }));

    const propio = !deps.browser;
    const navegador = deps.browser || (await playwright.chromium.launch({ args: ['--no-sandbox'] }));
    const limite = Math.min(opciones.concurrencia || 2, 4);
    try {
        return await mapearConcurrencia(urls, limite, async (u) => {
            try {
                const { reporte } = await escanearPagina(navegador, u, opciones);
                return reporte;
            } catch (err) {
                return { url: u, error: err && err.message ? err.message : String(err) };
            }
        });
    } finally {
        if (propio) await navegador.close().catch(() => {});
    }
}

module.exports = { escanearHeadless, escanearHeadlessLote };
