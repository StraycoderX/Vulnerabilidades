'use strict';

// Tests sin dependencias externas, con el runner integrado de Node (node:test).
const test = require('node:test');
const assert = require('node:assert');
const { URL } = require('url');

const { esDireccionPrivada, lookupFijo } = require('./src/net');
const { analizarCabeceras, graduarCSP } = require('./src/rules/headers');
const { analizarXSS } = require('./src/rules/xss');
const { analizarOfuscacion } = require('./src/rules/obfuscation');
const { analizarLibrerias, compararVersiones } = require('./src/rules/libraries');
const { analizar, exitCodePorHallazgos } = require('./src/engine');
const { aSARIF, huellasDeReportes, diffContraBaseline } = require('./src/report');

const ctx = (overrides) => ({
    url: new URL('https://ejemplo.com/'),
    statusCode: 200,
    headers: {},
    body: '',
    ...overrides,
});

test('anti-SSRF: detecta direcciones privadas/internas', () => {
    for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fd00::1']) {
        assert.strictEqual(esDireccionPrivada(ip), true, `${ip} debería ser privada`);
    }
});

test('anti-SSRF: permite direcciones públicas', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:2800:220:1::1']) {
        assert.strictEqual(esDireccionPrivada(ip), false, `${ip} debería ser pública`);
    }
});

test('cabeceras: marca ausencia de CSP/HSTS y cookie insegura', () => {
    const h = analizarCabeceras(ctx({ headers: { 'set-cookie': ['sid=abc; Path=/'] } }));
    assert.ok(h.some((f) => f.id === 'csp-ausente'));
    assert.ok(h.some((f) => f.id === 'hsts-ausente'));
    assert.ok(h.some((f) => f.id === 'cookie-insegura'));
});

test('cabeceras: gradúa una CSP permisiva', () => {
    const h = graduarCSP("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *");
    assert.ok(h.some((f) => f.id === 'csp-unsafe-inline'));
    assert.ok(h.some((f) => f.id === 'csp-unsafe-eval'));
    assert.ok(h.some((f) => f.id === 'csp-wildcard'));
});

test('cabeceras: CORS comodín con credenciales es severidad alta', () => {
    const h = analizarCabeceras(ctx({
        headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' },
    }));
    const cors = h.find((f) => f.id === 'cors-comodin-credenciales');
    assert.ok(cors && cors.severidad === 'alta');
});

test('cabeceras: prefijo __Host- mal configurado', () => {
    const h = analizarCabeceras(ctx({ headers: { 'set-cookie': ['__Host-sid=abc; Path=/admin'] } }));
    assert.ok(h.some((f) => f.id === 'cookie-prefijo-host'));
});

test('xss: detecta handlers inline, javascript: y mixed content', () => {
    const html = `<img src=x onerror="alert(1)"><a href="javascript:alert(2)">x</a><script src="http://cdn.io/a.js"></script>`;
    const h = analizarXSS(ctx({ body: html }));
    assert.ok(h.some((f) => f.id === 'evento-inline'));
    assert.ok(h.some((f) => f.id === 'javascript-uri'));
    assert.ok(h.some((f) => f.id === 'mixed-content'));
});

test('ofuscacion: detecta eval(atob()) y escapes largos', () => {
    const html = `<script>eval(atob("YWxlcnQoMSk="));var s="\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68";</script>`;
    const h = analizarOfuscacion(ctx({ body: html }));
    assert.ok(h.some((f) => f.mensaje.includes('atob')));
    assert.ok(h.some((f) => f.id === 'ofuscacion-escapes'));
});

test('engine: ordena por severidad y calcula exit code', () => {
    const reporte = analizar(ctx({ headers: { 'set-cookie': ['sid=1; Path=/'] }, body: '<img onerror="x()">' }));
    assert.ok(reporte.hallazgos.length > 0);
    // El primero debe ser de severidad >= que el último.
    const ord = { alta: 3, media: 2, baja: 1, info: 0 };
    assert.ok(ord[reporte.hallazgos[0].severidad] >= ord[reporte.hallazgos.at(-1).severidad]);
    assert.strictEqual(exitCodePorHallazgos(reporte), 1);
});

test('SARIF: estructura válida con reglas y resultados', () => {
    const reporte = analizar(ctx({ headers: {} }));
    const sarif = aSARIF([reporte]);
    assert.strictEqual(sarif.version, '2.1.0');
    assert.ok(Array.isArray(sarif.runs[0].results));
    assert.ok(sarif.runs[0].tool.driver.rules.length > 0);
    assert.ok(['error', 'warning', 'note'].includes(sarif.runs[0].results[0].level));
});

test('anti-rebinding: lookupFijo siempre devuelve la IP validada', () => {
    const lookup = lookupFijo('93.184.216.34', 4);
    let resultado;
    lookup('cualquier-host.com', {}, (err, address, family) => {
        resultado = { err, address, family };
    });
    assert.strictEqual(resultado.err, null);
    assert.strictEqual(resultado.address, '93.184.216.34');
    assert.strictEqual(resultado.family, 4);
});

test('librerias: detecta versiones vulnerables y compara semver', () => {
    assert.ok(compararVersiones('3.4.1', '3.5.0') < 0);
    assert.strictEqual(compararVersiones('3.5.0', '3.5.0'), 0);
    const vuln = analizarLibrerias(ctx({ body: '<script src="/js/jquery-3.4.1.min.js"></script>' }));
    assert.ok(vuln.some((f) => f.id === 'libreria-vulnerable' && f.mensaje.includes('jQuery')));
    const ok = analizarLibrerias(ctx({ body: '<script src="/js/jquery-3.7.1.min.js"></script>' }));
    assert.strictEqual(ok.length, 0);
});

test('baseline: diff reporta solo hallazgos nuevos', () => {
    const reporte = analizar(ctx({ headers: {} }));
    const baseline = huellasDeReportes([reporte]);
    // Sin cambios: nada nuevo.
    assert.strictEqual(diffContraBaseline(reporte, baseline).nuevos.length, 0);
    // Con baseline vacía: todo es nuevo.
    assert.strictEqual(diffContraBaseline(reporte, []).nuevos.length, reporte.hallazgos.length);
});
