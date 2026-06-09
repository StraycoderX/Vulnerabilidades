'use strict';

// Fuzzing/property-testing de las piezas críticas para la seguridad: el
// clasificador anti-SSRF y el parser HTML. PRNG con semilla fija => reproducible.
const test = require('node:test');
const assert = require('node:assert');
const { URL } = require('url');
const { esDireccionPrivada } = require('./src/net');
const { parsearHTML, parsearAtributos } = require('./src/parser');
const { analizar } = require('./src/engine');
const { detectarErrorSQL } = require('./src/active');

function mulberry32(a) {
    return function () {
        a |= 0;
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
const rnd = mulberry32(0xc0ffee);
const ri = (n) => Math.floor(rnd() * n);

test('fuzz: esDireccionPrivada nunca lanza y devuelve booleano (basura aleatoria)', () => {
    for (let i = 0; i < 10000; i++) {
        let s = '';
        const len = ri(40);
        for (let j = 0; j < len; j++) s += String.fromCharCode(33 + ri(94));
        assert.strictEqual(typeof esDireccionPrivada(s), 'boolean', `entrada: ${s}`);
    }
});

test('fuzz: IPs de rangos privados/reservados SIEMPRE se bloquean', () => {
    const priv = () => {
        switch (ri(7)) {
            case 0: return `10.${ri(256)}.${ri(256)}.${ri(256)}`;
            case 1: return `192.168.${ri(256)}.${ri(256)}`;
            case 2: return `172.${16 + ri(16)}.${ri(256)}.${ri(256)}`;
            case 3: return `127.${ri(256)}.${ri(256)}.${ri(256)}`;
            case 4: return `169.254.${ri(256)}.${ri(256)}`;
            case 5: return `100.${64 + ri(64)}.${ri(256)}.${ri(256)}`;
            default: return `${224 + ri(32)}.${ri(256)}.${ri(256)}.${ri(256)}`;
        }
    };
    for (let i = 0; i < 8000; i++) {
        const ip = priv();
        assert.strictEqual(esDireccionPrivada(ip), true, `debería bloquear ${ip}`);
    }
});

test('fuzz: IPs de rangos claramente públicos NUNCA se bloquean', () => {
    const pub = () => {
        const primero = [8, 9, 11 + ri(5), 50 + ri(10), 200 + ri(3)][ri(5)];
        return `${primero}.${ri(256)}.${ri(256)}.${ri(256)}`;
    };
    for (let i = 0; i < 8000; i++) {
        const ip = pub();
        assert.strictEqual(esDireccionPrivada(ip), false, `no debería bloquear ${ip}`);
    }
});

test('fuzz: parsearHTML/parsearAtributos nunca lanzan con entrada aleatoria', () => {
    const chars = '<>="\'/ \tabcdivscript-\n&;{}.:';
    for (let i = 0; i < 6000; i++) {
        let s = '';
        const len = ri(300);
        for (let j = 0; j < len; j++) s += chars[ri(chars.length)];
        const t0 = Date.now();
        const { elementos } = parsearHTML(s);
        assert.ok(Array.isArray(elementos));
        assert.ok(Date.now() - t0 < 250, 'parseo demasiado lento');
        parsearAtributos(s);
    }
});

test('fuzz: el parser no se degrada (O(n)) con entradas patológicas grandes', () => {
    const muchasEtiquetas = '<a x="1">'.repeat(100000); // ~0.9 MB
    let t0 = Date.now();
    parsearHTML(muchasEtiquetas);
    assert.ok(Date.now() - t0 < 1500, 'muchas etiquetas: demasiado lento');

    const comillasSinCerrar = '<"'.repeat(400000); // ~0.8 MB sin ningún '>'
    t0 = Date.now();
    parsearHTML(comillasSinCerrar);
    assert.ok(Date.now() - t0 < 1500, 'comillas patológicas: demasiado lento');

    const scriptEnorme = '<script>' + 'a'.repeat(800000); // script sin cerrar
    t0 = Date.now();
    parsearHTML(scriptEnorme);
    assert.ok(Date.now() - t0 < 1500, 'script enorme: demasiado lento');
});

test('fuzz: las reglas no se degradan con HTML hostil grande (anti-DoS)', () => {
    const casos = [
        '<form>'.repeat(400000), // formularios sin cerrar (era O(n^2))
        '<a href="x?next=//evil">l</a>'.repeat(60000),
        '<img onerror="x()">'.repeat(60000),
        '<script>eval(atob("YQ=="))</script>'.repeat(20000),
        '<'.repeat(800000) + 'a x="' + '"'.repeat(400000),
    ];
    for (const body of casos) {
        const ctx = { url: new URL('https://hostil.test/'), statusCode: 200, headers: {}, body };
        const t0 = Date.now();
        analizar(ctx);
        const ms = Date.now() - t0;
        assert.ok(ms < 2500, `reglas demasiado lentas (${ms} ms) con ${(body.length / 1024) | 0} KB`);
    }
});

test('fuzz: las firmas SQL no se degradan ante respuestas hostiles (anti-DoS)', () => {
    for (const semilla of ['SQL syntax ', 'Warning ', 'PostgreSQL ']) {
        const body = semilla.repeat(300000); // ~3 MB repitiendo el token previo
        const t0 = Date.now();
        detectarErrorSQL(body);
        const ms = Date.now() - t0;
        assert.ok(ms < 1500, `firmas SQL demasiado lentas (${ms} ms) con "${semilla}"`);
    }
});
