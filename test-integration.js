'use strict';

// Tests de INTEGRACIÓN: levantan un servidor HTTP local y ejercitan las rutas de
// red reales (descarga, crawl, modo activo, escaneo autenticado). El allowlist de
// loopback se activa solo aquí mediante la variable de entorno.
process.env.VULN_TEST_ALLOW_LOOPBACK = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { escanear, escanearDetallado } = require('./src/engine');
const { escanearHeadless } = require('./src/headless');
const { rastrear } = require('./src/crawl');
const { validarObjetivo, descargar } = require('./src/net');

let servidor;
let base;

test.before(async () => {
    servidor = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost');
        const q = url.searchParams.get('q') || '';

        if (url.pathname === '/echo') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`x-prueba=${req.headers['x-prueba'] || ''}; cookie=${req.headers.cookie || ''}`);
            return;
        }

        if (url.pathname === '/page2') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body><iframe src="x"></iframe></body></html>');
            return;
        }

        // Open redirect: redirige al valor del parámetro `next` sin validar.
        if (url.pathname === '/redir') {
            res.writeHead(302, { Location: url.searchParams.get('next') || '/' });
            res.end();
            return;
        }

        // Vulnerable a SQLi (error-based) y SSTI según el contenido de `q`.
        if (url.pathname === '/buscar') {
            let salida = q;
            if (q.includes("'")) salida += ' — You have an error in your SQL syntax near MySQL';
            if (q.includes('{{73*137}}')) salida = salida.replace('{{73*137}}', '10001');
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<html><body>res: ${salida}</body></html>`);
            return;
        }

        // Página principal: insegura a propósito y refleja `q` sin escapar.
        res.writeHead(200, {
            'Content-Type': 'text/html',
            'Set-Cookie': 'sid=abc; Path=/',
        });
        res.end(`<html><body>
            <img src=p onerror="alert(1)">
            <script src="/js/jquery-1.12.4.min.js"></script>
            <a href="/page2">2</a>
            <a href="http://externo.example/x">ext</a>
            <div>buscado: ${q}</div>
        </body></html>`);
    });
    await new Promise((r) => servidor.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${servidor.address().port}`;
});

test.after(() => servidor && servidor.close());

test('integración: escaneo detecta hallazgos reales', async () => {
    const reporte = await escanear(`${base}/`);
    const ids = reporte.hallazgos.map((f) => f.id);
    assert.ok(ids.includes('csp-ausente'));
    assert.ok(ids.includes('cookie-insegura'));
    assert.ok(ids.includes('evento-inline'));
    assert.ok(ids.includes('libreria-vulnerable'));
});

test('integración: crawl sigue solo el mismo origen', async () => {
    const reportes = await rastrear(`${base}/`, { crawl: 1, maxPaginas: 10, concurrencia: 3 });
    const urls = reportes.map((r) => r.url);
    assert.ok(urls.some((u) => u.endsWith('/page2')));
    assert.ok(!urls.some((u) => u.includes('externo.example')));
});

test('integración: modo activo detecta XSS reflejado', async () => {
    const { reporte } = await escanearDetallado(`${base}/?q=hola`, { active: true, authorized: true });
    assert.ok(reporte.hallazgos.some((f) => f.id === 'xss-reflejado'));
});

test('integración: modo activo detecta SSTI y SQLi', async () => {
    const { reporte } = await escanearDetallado(`${base}/buscar?q=hola`, { active: true, authorized: true });
    const ids = reporte.hallazgos.map((f) => f.id);
    assert.ok(ids.includes('ssti'), 'debería detectar SSTI');
    assert.ok(ids.includes('sqli-error'), 'debería detectar SQLi');
});

test('integración: modo activo detecta open redirect', async () => {
    const { reporte } = await escanearDetallado(`${base}/redir?next=/`, { active: true, authorized: true });
    assert.ok(reporte.hallazgos.some((f) => f.id === 'open-redirect-activo'));
});

test('integración: orquestación headless (Playwright simulado)', async () => {
    // Playwright falso que emite una violación de CSP y devuelve un DOM con un
    // manejador inline, para verificar el cableado y el análisis del DOM renderizado.
    const handlers = {};
    const page = {
        on: (ev, cb) => ((handlers[ev] = handlers[ev] || []).push(cb)),
        goto: async () => {
            (handlers.console || []).forEach((cb) =>
                cb({ text: () => 'Refused to execute inline script: Content Security Policy' })
            );
            return { status: () => 200, headers: () => ({}) };
        },
        content: async () => '<html><body><img src=x onerror="roba()"></body></html>',
    };
    const playwrightFalso = {
        chromium: {
            launch: async () => ({
                newContext: async () => ({ newPage: async () => page }),
                close: async () => {},
            }),
        },
    };

    const { reporte } = await escanearHeadless(`${base}/`, {}, { playwright: playwrightFalso });
    const ids = reporte.hallazgos.map((f) => f.id);
    assert.ok(ids.includes('csp-violacion-runtime'), 'CSP runtime');
    assert.ok(ids.includes('evento-inline'), 'analiza el DOM renderizado');
});

test('integración: escaneo autenticado envía cabeceras y cookie', async () => {
    const target = await validarObjetivo(`${base}/echo`);
    const { body } = await descargar(target, { headers: { 'x-prueba': 'ok', Cookie: 'sesion=1' } });
    assert.ok(body.includes('x-prueba=ok'));
    assert.ok(body.includes('cookie=sesion=1'));
});
