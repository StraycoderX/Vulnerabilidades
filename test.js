'use strict';

// Tests sin dependencias externas, usando el runner integrado de Node (node:test).
const test = require('node:test');
const assert = require('node:assert');
const { URL } = require('url');
const {
    esDireccionPrivada,
    analizarCabeceras,
    analizarXSS,
    analizarOfuscacion,
    exitCodePorHallazgos,
} = require('./index.js');

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
    const url = new URL('https://ejemplo.com/');
    const h = analizarCabeceras(url, { 'set-cookie': ['sid=abc; Path=/'] });
    assert.ok(h.some((f) => f.mensaje.includes('CSP')));
    assert.ok(h.some((f) => f.mensaje.includes('HSTS')));
    assert.ok(h.some((f) => f.categoria === 'cookies'));
});

test('cabeceras: no marca CSP/HSTS si están presentes', () => {
    const url = new URL('https://ejemplo.com/');
    const h = analizarCabeceras(url, {
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'strict-transport-security': 'max-age=31536000',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()',
    });
    assert.ok(!h.some((f) => f.mensaje.includes('CSP')));
    assert.ok(!h.some((f) => f.mensaje.includes('HSTS')));
});

test('xss: detecta handlers inline, javascript: y mixed content', () => {
    const url = new URL('https://ejemplo.com/');
    const html = `<img src=x onerror="alert(1)"><a href="javascript:alert(2)">x</a><script src="http://cdn.io/a.js"></script>`;
    const h = analizarXSS(url, html);
    assert.ok(h.some((f) => f.mensaje.includes('on*')));
    assert.ok(h.some((f) => f.mensaje.includes('javascript:')));
    assert.ok(h.some((f) => f.mensaje.includes('mixed content')));
});

test('ofuscacion: detecta eval(atob()) y escapes largos', () => {
    const html = `<script>eval(atob("YWxlcnQoMSk="));var s="\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68";</script>`;
    const h = analizarOfuscacion(html);
    assert.ok(h.some((f) => f.mensaje.includes('atob')));
    assert.ok(h.some((f) => f.mensaje.toLowerCase().includes('hex')));
});

test('exit code: 1 si hay hallazgos altos/medios', () => {
    assert.strictEqual(exitCodePorHallazgos({ hallazgos: [{ severidad: 'media' }] }), 1);
    assert.strictEqual(exitCodePorHallazgos({ hallazgos: [{ severidad: 'info' }] }), 0);
});
