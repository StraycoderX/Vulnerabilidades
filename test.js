'use strict';

// Tests sin dependencias externas, con el runner integrado de Node (node:test).
const test = require('node:test');
const assert = require('node:assert');
const { URL } = require('url');

const { esDireccionPrivada, lookupFijo, proxyParaUrl } = require('./src/net');
const { analizarCabeceras, graduarCSP } = require('./src/rules/headers');
const { analizarXSS } = require('./src/rules/xss');
const { analizarOfuscacion } = require('./src/rules/obfuscation');
const { analizarLibrerias, compararVersiones } = require('./src/rules/libraries');
const { analizarTLS } = require('./src/rules/tls');
const { analizarActivo } = require('./src/rules/active');
const { analizarHeadless } = require('./src/rules/headless');
const { parsearHTML, parsearAtributos } = require('./src/parser');
const { mapearConcurrencia } = require('./src/pool');
const { detectarReflejo, detectarErrorSQL } = require('./src/active');
const { extraerEnlacesMismoOrigen } = require('./src/crawl');
const { analizar, exitCodePorHallazgos } = require('./src/engine');
const { aSARIF, huellasDeReportes, diffContraBaseline, aHTML, limpiarControl } = require('./src/report');

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
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:2800:220:1::1', '100.128.0.1', '192.0.1.1']) {
        assert.strictEqual(esDireccionPrivada(ip), false, `${ip} debería ser pública`);
    }
});

test('anti-SSRF: rangos reservados y IPv6 mapped en hex', () => {
    for (const ip of ['100.64.0.1', '192.0.0.1', '198.18.0.5', '224.0.0.1', '255.255.255.255', '::ffff:7f00:1', 'ff02::1']) {
        assert.strictEqual(esDireccionPrivada(ip), true, `${ip} debería bloquearse`);
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

test('cabeceras: una fuente https concreta NO es esquema permisivo (sin FP)', () => {
    const ok = graduarCSP("default-src 'self'; script-src https://cdn.example.com 'self'");
    assert.ok(!ok.some((f) => f.id === 'csp-wildcard'), 'https://host concreto no debe marcarse');
    const malo = graduarCSP('script-src https:');
    assert.ok(malo.some((f) => f.id === 'csp-wildcard'), 'https: a secas sí es permisivo');
});

test('reporte: limpiarControl elimina secuencias de escape de terminal', () => {
    assert.strictEqual(limpiarControl('a\x1b[31mROJO\x1b[0mb'), 'a[31mROJO[0mb');
    assert.strictEqual(limpiarControl('x\x07\x00y'), 'xy');
    assert.strictEqual(limpiarControl(null), '');
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

test('anti-rebinding: lookupFijo honra la opción all (autoSelectFamily, Node 20+)', () => {
    const lookup = lookupFijo('93.184.216.34', 4);
    // all:true debe devolver un ARRAY [{address, family}] (Happy Eyeballs).
    let arr;
    lookup('host', { all: true }, (err, addrs) => (arr = { err, addrs }));
    assert.strictEqual(arr.err, null);
    assert.deepStrictEqual(arr.addrs, [{ address: '93.184.216.34', family: 4 }]);
    // firma antigua (options es la función callback).
    let legacy;
    lookup('host', (err, address) => (legacy = address));
    assert.strictEqual(legacy, '93.184.216.34');
    // IPv6: deduce family 6 si no se pasa.
    let v6;
    lookupFijo('2606:2800:220:1::1')('host', { all: true }, (e, a) => (v6 = a));
    assert.deepStrictEqual(v6, [{ address: '2606:2800:220:1::1', family: 6 }]);
});

test('proxy: proxyParaUrl honra protocolo y NO_PROXY', () => {
    const limpiar = () => {
        delete process.env.HTTP_PROXY;
        delete process.env.HTTPS_PROXY;
        delete process.env.NO_PROXY;
    };
    limpiar();
    try {
        assert.strictEqual(proxyParaUrl(new URL('http://x.com/')), null);
        process.env.HTTP_PROXY = 'http://proxy.local:8080';
        assert.strictEqual(proxyParaUrl(new URL('http://x.com/')).host, 'proxy.local:8080');
        // https usa HTTPS_PROXY, no HTTP_PROXY
        assert.strictEqual(proxyParaUrl(new URL('https://x.com/')), null);
        process.env.HTTPS_PROXY = 'http://sproxy.local:3128';
        assert.strictEqual(proxyParaUrl(new URL('https://x.com/')).host, 'sproxy.local:3128');
        // NO_PROXY excluye el dominio (y sus subdominios)
        process.env.NO_PROXY = 'x.com';
        assert.strictEqual(proxyParaUrl(new URL('http://x.com/')), null);
        assert.strictEqual(proxyParaUrl(new URL('http://sub.x.com/')), null);
        assert.strictEqual(proxyParaUrl(new URL('http://otro.com/')).host, 'proxy.local:8080');
    } finally {
        limpiar();
    }
});

test('librerias: detecta versiones vulnerables y compara semver', () => {
    assert.ok(compararVersiones('3.4.1', '3.5.0') < 0);
    assert.strictEqual(compararVersiones('3.5.0', '3.5.0'), 0);
    const vuln = analizarLibrerias(ctx({ body: '<script src="/js/jquery-3.4.1.min.js"></script>' }));
    assert.ok(vuln.some((f) => f.id === 'libreria-vulnerable' && f.mensaje.includes('jQuery')));
    const ok = analizarLibrerias(ctx({ body: '<script src="/js/jquery-3.7.1.min.js"></script>' }));
    assert.strictEqual(ok.length, 0);
});

test('parser: tokeniza etiquetas, atributos y contenido de script', () => {
    const { elementos } = parsearHTML(
        `<!-- c --><div class="x" data-y='z'></div><img src=a onerror="alert(1)"><script src="lib.js">var a=1;</script>`
    );
    const tags = elementos.map((e) => e.tag);
    assert.deepStrictEqual(tags, ['div', 'img', 'script']);
    assert.strictEqual(elementos[0].attrs.class, 'x');
    assert.strictEqual(elementos[0].attrs['data-y'], 'z');
    assert.strictEqual(elementos[1].attrs.onerror, 'alert(1)');
    assert.strictEqual(elementos[2].attrs.src, 'lib.js');
    assert.strictEqual(elementos[2].contenido, 'var a=1;');
});

test("parser: no confunde '>' dentro de atributos entrecomillados", () => {
    const { elementos } = parsearHTML(`<a title="1 > 0" href="x">`);
    assert.strictEqual(elementos.length, 1);
    assert.strictEqual(elementos[0].attrs.title, '1 > 0');
    assert.strictEqual(elementos[0].attrs.href, 'x');
});

test('parser: atributos sin valor', () => {
    const attrs = parsearAtributos('disabled checked type=text');
    assert.strictEqual(attrs.disabled, '');
    assert.strictEqual(attrs.type, 'text');
});

test('tls: protocolo obsoleto y certificado caducado son severidad alta', () => {
    const obsoleto = analizarTLS(ctx({ tls: { protocol: 'TLSv1', validTo: null, error: null } }));
    assert.ok(obsoleto.some((f) => f.id === 'tls-protocolo-obsoleto' && f.severidad === 'alta'));

    const ayer = new Date(Date.now() - 86400000).toUTCString();
    const caducado = analizarTLS(ctx({ tls: { protocol: 'TLSv1.3', validTo: ayer, error: null } }));
    assert.ok(caducado.some((f) => f.id === 'tls-cert-caducado' && f.severidad === 'alta'));

    const sano = analizarTLS(ctx({ tls: { protocol: 'TLSv1.3', validTo: new Date(Date.now() + 100 * 86400000).toUTCString(), error: null } }));
    assert.strictEqual(sano.length, 0);

    assert.strictEqual(analizarTLS(ctx({ tls: { error: 'timeout' } })).length, 0);
});

test('pool: respeta el límite de concurrencia y conserva el orden', async () => {
    let activos = 0;
    let maxActivos = 0;
    const resultado = await mapearConcurrencia([1, 2, 3, 4, 5, 6], 2, async (x) => {
        activos++;
        maxActivos = Math.max(maxActivos, activos);
        await new Promise((r) => setTimeout(r, 5));
        activos--;
        return x * 10;
    });
    assert.deepStrictEqual(resultado, [10, 20, 30, 40, 50, 60]);
    assert.ok(maxActivos <= 2, `maxActivos=${maxActivos} debería ser <= 2`);
});

test('librerias: detecta versiones de dos partes (x.y)', () => {
    const r = analizarLibrerias(ctx({ body: '<script src="/lib/jquery-1.4.min.js"></script>' }));
    assert.ok(r.some((f) => f.id === 'libreria-vulnerable' && f.mensaje.includes('1.4')));
});

test('pool: una tarea que lanza no tumba el lote', async () => {
    const res = await mapearConcurrencia([1, 2, 3], 2, async (x) => {
        if (x === 2) throw new Error('boom');
        return x * 10;
    });
    assert.strictEqual(res[0], 10);
    assert.ok(res[1] && res[1].error && res[1].error.includes('boom'));
    assert.strictEqual(res[2], 30);
});

test('librerias: detecta firmas ampliadas (Handlebars, Axios)', () => {
    const r = analizarLibrerias(ctx({
        body: '<script src="/handlebars-4.0.0.min.js"></script><script src="/axios-0.18.0.min.js"></script>',
    }));
    assert.ok(r.some((f) => f.mensaje.includes('Handlebars')));
    assert.ok(r.some((f) => f.mensaje.includes('Axios')));
});

test('activo: detección de reflejo y de error SQL', () => {
    const marcador = 'xZapabcd"\'<>';
    assert.strictEqual(detectarReflejo(`<p>${marcador}</p>`, marcador), true);
    assert.strictEqual(detectarReflejo('<p>xZapabcd&quot;&lt;&gt;</p>', marcador), false);
    assert.strictEqual(detectarErrorSQL('... You have an error in your SQL syntax; check the MySQL ...'), true);
    assert.strictEqual(detectarErrorSQL('pagina normal sin errores'), false);
});

test('activo: la regla mapea cada tipo de sonda a su hallazgo', () => {
    const h = analizarActivo(ctx({
        active: [
            { tipo: 'xss', parametro: 'q', detectado: true },
            { tipo: 'ssti', parametro: 'name', detectado: true },
            { tipo: 'sqli', parametro: 'id', detectado: true },
            { tipo: 'open-redirect', parametro: 'next', detectado: false },
        ],
    }));
    const ids = h.map((f) => f.id);
    assert.ok(ids.includes('xss-reflejado'));
    assert.ok(ids.includes('ssti'));
    assert.ok(ids.includes('sqli-error'));
    assert.ok(!ids.includes('open-redirect-activo')); // detectado:false no genera hallazgo
});

test('headless: regla de CSP runtime y mapeo de DOM-XSS', () => {
    const h = analizarHeadless(ctx({ headless: { violacionesCSP: ['Refused ... Content Security Policy'], erroresJS: [] } }));
    assert.ok(h.some((f) => f.id === 'csp-violacion-runtime'));
    // sin datos headless no produce hallazgos
    assert.strictEqual(analizarHeadless(ctx({})).length, 0);
    // el tipo dom-xss se mapea vía la regla activa
    const d = analizarActivo(ctx({ active: [{ tipo: 'dom-xss', parametro: 'q', detectado: true }] }));
    assert.ok(d.some((f) => f.id === 'dom-xss' && f.severidad === 'alta'));
});

test('crawl: extrae solo enlaces del mismo origen', () => {
    const base = new URL('https://sitio.test/a');
    const dom = parsearHTML(
        '<a href="/b">b</a><a href="https://sitio.test/c#x">c</a><a href="https://otro.test/d">d</a><a href="mailto:x@y.z">m</a>'
    );
    const enlaces = extraerEnlacesMismoOrigen(dom, base);
    assert.ok(enlaces.includes('https://sitio.test/b'));
    assert.ok(enlaces.includes('https://sitio.test/c'));
    assert.ok(!enlaces.some((u) => u.includes('otro.test')));
    assert.ok(!enlaces.some((u) => u.startsWith('mailto')));
});

test('reporte HTML: genera documento con hallazgos escapados', () => {
    const html = aHTML([{ url: 'https://x.test/', hallazgos: [{ severidad: 'alta', categoria: 'xss', mensaje: '<script>', detalle: null }] }]);
    assert.ok(html.includes('<!doctype html>'));
    assert.ok(html.includes('&lt;script&gt;')); // el mensaje va escapado
    assert.ok(html.includes('ALTA'));
});

test('baseline: diff reporta solo hallazgos nuevos', () => {
    const reporte = analizar(ctx({ headers: {} }));
    const baseline = huellasDeReportes([reporte]);
    // Sin cambios: nada nuevo.
    assert.strictEqual(diffContraBaseline(reporte, baseline).nuevos.length, 0);
    // Con baseline vacía: todo es nuevo.
    assert.strictEqual(diffContraBaseline(reporte, []).nuevos.length, reporte.hallazgos.length);
});
