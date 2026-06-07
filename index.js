'use strict';

const readline = require('readline');
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

// --- Configuración de seguridad -------------------------------------------
const REQUEST_TIMEOUT_MS = 10000; // Aborta conexiones colgadas
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB: evita agotar memoria (DoS)
const MAX_REDIRECTS = 5; // Límite de saltos para evitar bucles de redirección

// Niveles de severidad (de mayor a menor), con orden y color para el reporte.
const SEVERIDAD = {
    alta: { orden: 3, etiqueta: 'ALTA', color: '\x1b[31m' },
    media: { orden: 2, etiqueta: 'MEDIA', color: '\x1b[33m' },
    baja: { orden: 1, etiqueta: 'BAJA', color: '\x1b[36m' },
    info: { orden: 0, etiqueta: 'INFO', color: '\x1b[90m' },
};
const RESET = '\x1b[0m';

// --- Protección anti-SSRF --------------------------------------------------
// Bloquea destinos hacia rangos internos/privados para que la herramienta no
// pueda usarse para alcanzar metadatos de cloud o servicios internos.
function esDireccionPrivada(ip) {
    let dir = ip;
    // Normaliza IPv4 embebido en IPv6 (p. ej. ::ffff:127.0.0.1) — bypass clásico.
    const mapped = dir.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) dir = mapped[1];

    const tipo = net.isIP(dir);
    if (tipo === 4) {
        const o = dir.split('.').map(Number);
        return (
            o[0] === 10 ||
            o[0] === 127 ||
            (o[0] === 169 && o[1] === 254) || // link-local / metadata cloud
            (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
            (o[0] === 192 && o[1] === 168) ||
            o[0] === 0
        );
    }
    if (tipo === 6) {
        const v = dir.toLowerCase();
        return (
            v === '::1' ||           // loopback
            v.startsWith('fc') ||    // unique local
            v.startsWith('fd') ||
            v.startsWith('fe80') ||  // link-local
            v === '::'
        );
    }
    return false;
}

// Valida el esquema y resuelve el host para rechazar objetivos internos.
async function validarObjetivo(rawUrl) {
    let url;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new Error('URL inválida. Usa el formato http(s)://dominio/ruta');
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error(`Protocolo no permitido: ${url.protocol} (solo http/https)`);
    }

    const { address } = await dns.lookup(url.hostname);
    if (esDireccionPrivada(address)) {
        throw new Error(`Destino bloqueado por seguridad (dirección interna/privada: ${address})`);
    }

    return url;
}

// --- Descarga del HTML con controles de seguridad --------------------------
// Devuelve { statusCode, headers, body }.
function descargar(url, redirecciones = 0) {
    return new Promise((resolve, reject) => {
        const cliente = url.protocol === 'https:' ? https : http;

        const req = cliente.get(
            url,
            { rejectUnauthorized: true }, // verificación TLS explícita
            (resp) => {
                const { statusCode, headers } = resp;

                // Redirecciones controladas (con revalidación anti-SSRF).
                if (statusCode >= 300 && statusCode < 400 && headers.location) {
                    resp.resume(); // descarta el cuerpo
                    if (redirecciones >= MAX_REDIRECTS) {
                        return reject(new Error('Demasiadas redirecciones'));
                    }
                    const destino = new URL(headers.location, url);
                    return validarObjetivo(destino.href)
                        .then((u) => resolve(descargar(u, redirecciones + 1)))
                        .catch(reject);
                }

                if (statusCode < 200 || statusCode >= 300) {
                    resp.resume();
                    return reject(new Error(`Respuesta HTTP ${statusCode}`));
                }

                const trozos = [];
                let total = 0;

                resp.on('data', (chunk) => {
                    total += chunk.length;
                    if (total > MAX_RESPONSE_BYTES) {
                        req.destroy();
                        return reject(
                            new Error(`Respuesta demasiado grande (> ${MAX_RESPONSE_BYTES} bytes)`)
                        );
                    }
                    trozos.push(chunk);
                });

                resp.on('end', () =>
                    resolve({ statusCode, headers, body: Buffer.concat(trozos).toString('utf8') })
                );
                resp.on('error', reject);
            }
        );

        req.setTimeout(REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`Tiempo de espera agotado (${REQUEST_TIMEOUT_MS} ms)`));
        });
        req.on('error', reject);
    });
}

// --- Motor de análisis -----------------------------------------------------
function crearHallazgo(severidad, categoria, mensaje, detalle) {
    return { severidad, categoria, mensaje, detalle: detalle || null };
}

// 1) Cabeceras de seguridad: la defensa de primera línea.
function analizarCabeceras(url, headers) {
    const h = {};
    for (const k of Object.keys(headers)) h[k.toLowerCase()] = headers[k];
    const hallazgos = [];
    const esHttps = url.protocol === 'https:';

    if (!h['content-security-policy']) {
        hallazgos.push(
            crearHallazgo('media', 'cabeceras', 'Falta Content-Security-Policy (CSP)',
                'CSP es la principal mitigación contra XSS e inyección de recursos.')
        );
    }
    if (esHttps && !h['strict-transport-security']) {
        hallazgos.push(
            crearHallazgo('media', 'cabeceras', 'Falta Strict-Transport-Security (HSTS)',
                'Permite ataques de downgrade/MITM en la primera conexión.')
        );
    }
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) {
        hallazgos.push(
            crearHallazgo('baja', 'cabeceras', 'Falta protección anti-clickjacking',
                'Sin X-Frame-Options ni CSP frame-ancestors.')
        );
    }
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
        hallazgos.push(
            crearHallazgo('baja', 'cabeceras', 'Falta X-Content-Type-Options: nosniff',
                'El navegador podría adivinar el tipo MIME (MIME sniffing).')
        );
    }
    if (!h['referrer-policy']) {
        hallazgos.push(crearHallazgo('info', 'cabeceras', 'Falta Referrer-Policy'));
    }
    if (!h['permissions-policy']) {
        hallazgos.push(crearHallazgo('info', 'cabeceras', 'Falta Permissions-Policy'));
    }
    if (h['server'] || h['x-powered-by']) {
        hallazgos.push(
            crearHallazgo('info', 'fingerprinting', 'Expone tecnología del servidor',
                [h['server'] && `Server: ${h['server']}`, h['x-powered-by'] && `X-Powered-By: ${h['x-powered-by']}`]
                    .filter(Boolean).join(' | '))
        );
    }

    // Cookies sin atributos de seguridad.
    const cookies = [].concat(h['set-cookie'] || []);
    for (const cookie of cookies) {
        const nombre = cookie.split('=')[0];
        const faltan = [];
        if (esHttps && !/;\s*secure/i.test(cookie)) faltan.push('Secure');
        if (!/;\s*httponly/i.test(cookie)) faltan.push('HttpOnly');
        if (!/;\s*samesite/i.test(cookie)) faltan.push('SameSite');
        if (faltan.length) {
            hallazgos.push(
                crearHallazgo('media', 'cookies', `Cookie "${nombre}" sin atributos: ${faltan.join(', ')}`)
            );
        }
    }

    return hallazgos;
}

// 2) Vectores de XSS en el HTML (regex ligera; un parser daría más precisión).
function analizarXSS(url, html) {
    const hallazgos = [];

    const scripts = html.match(/<\s*script\b[^>]*>/gi) || [];
    if (scripts.length) {
        hallazgos.push(
            crearHallazgo('info', 'xss', `${scripts.length} etiqueta(s) <script> presentes`,
                'Revisa que los scripts inline usen nonce/hash y no reflejen entrada de usuario.')
        );
    }

    const handlers = html.match(/\son[a-z]+\s*=\s*["'][^"']*["']/gi) || [];
    if (handlers.length) {
        hallazgos.push(
            crearHallazgo('media', 'xss', `${handlers.length} manejador(es) de evento inline (on*=)`,
                muestra(handlers))
        );
    }

    const jsUris = html.match(/(?:href|src)\s*=\s*["']\s*javascript:[^"']*["']/gi) || [];
    if (jsUris.length) {
        hallazgos.push(crearHallazgo('media', 'xss', `${jsUris.length} URI javascript: detectada(s)`, muestra(jsUris)));
    }

    const domSinks = html.match(/\b(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b/gi) || [];
    if (domSinks.length) {
        hallazgos.push(
            crearHallazgo('baja', 'xss', `Sumideros DOM peligrosos: ${[...new Set(domSinks.map((s) => s.toLowerCase()))].join(', ')}`,
                'Si reciben entrada del usuario sin sanitizar pueden causar DOM-XSS.')
        );
    }

    const frames = html.match(/<\s*(iframe|object|embed)\b[^>]*>/gi) || [];
    if (frames.length) {
        hallazgos.push(crearHallazgo('baja', 'contenido', `${frames.length} marco(s) embebido(s) (iframe/object/embed)`));
    }

    // Mixed content: recursos http:// en una página https.
    if (url.protocol === 'https:') {
        const mixed = html.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi) || [];
        if (mixed.length) {
            hallazgos.push(
                crearHallazgo('media', 'contenido', `${mixed.length} recurso(s) cargados por HTTP en página HTTPS (mixed content)`,
                    muestra(mixed))
            );
        }
    }

    // Formularios sin token anti-CSRF aparente.
    const forms = html.match(/<\s*form\b[^>]*>[\s\S]*?<\s*\/\s*form\s*>/gi) || [];
    const sinToken = forms.filter((f) => !/csrf|token|authenticity|_token|nonce/i.test(f));
    if (sinToken.length) {
        hallazgos.push(
            crearHallazgo('baja', 'csrf', `${sinToken.length} de ${forms.length} formulario(s) sin token anti-CSRF aparente`,
                'Heurística: no se halló un campo con nombre csrf/token/nonce.')
        );
    }

    return hallazgos;
}

// 3) Heurística de código ofuscado / sospechoso.
function analizarOfuscacion(html) {
    const hallazgos = [];
    const patrones = [
        [/\beval\s*\(/gi, 'eval()'],
        [/\bFunction\s*\(\s*["'`]/gi, 'new Function(string)'],
        [/\batob\s*\(/gi, 'atob() (base64)'],
        [/\bunescape\s*\(/gi, 'unescape()'],
        [/String\.fromCharCode\s*\(/gi, 'String.fromCharCode()'],
        [/\beval\s*\(\s*atob\s*\(/gi, 'eval(atob()) — patrón típico de payload oculto'],
    ];
    for (const [re, etiqueta] of patrones) {
        const n = (html.match(re) || []).length;
        if (n) hallazgos.push(crearHallazgo('media', 'ofuscacion', `Patrón sospechoso: ${etiqueta} ×${n}`));
    }

    // Secuencias de escape largas (ofuscación por codificación).
    const hexes = html.match(/(?:\\x[0-9a-f]{2}){8,}/gi) || [];
    const unis = html.match(/(?:\\u[0-9a-f]{4}){6,}/gi) || [];
    if (hexes.length || unis.length) {
        hallazgos.push(
            crearHallazgo('media', 'ofuscacion', 'Cadenas con escapes hex/unicode largos',
                `\\xNN: ${hexes.length}, \\uNNNN: ${unis.length} (posible payload codificado).`)
        );
    }

    return hallazgos;
}

function muestra(arr, n = 3) {
    return arr.slice(0, n).map((s) => s.trim().slice(0, 120)).join(' || ');
}

// Ejecuta todo el análisis y devuelve la lista de hallazgos ordenada.
function analizar(url, statusCode, headers, html) {
    const hallazgos = [
        ...analizarCabeceras(url, headers),
        ...analizarXSS(url, html),
        ...analizarOfuscacion(html),
    ];
    hallazgos.sort((a, b) => SEVERIDAD[b.severidad].orden - SEVERIDAD[a.severidad].orden);
    return { url: url.href, statusCode, totalHallazgos: hallazgos.length, hallazgos };
}

// --- Reporte ---------------------------------------------------------------
function imprimirReporte(reporte, usarColor = true) {
    const c = (s, color) => (usarColor ? `${color}${s}${RESET}` : s);
    console.log(`\nAnálisis de ${reporte.url} (HTTP ${reporte.statusCode})`);
    if (!reporte.hallazgos.length) {
        console.log('  Sin hallazgos.');
        return;
    }
    for (const f of reporte.hallazgos) {
        const sev = SEVERIDAD[f.severidad];
        console.log(`  [${c(sev.etiqueta, sev.color)}] (${f.categoria}) ${f.mensaje}`);
        if (f.detalle) console.log(`         ${f.detalle}`);
    }
    const resumen = {};
    for (const f of reporte.hallazgos) resumen[f.severidad] = (resumen[f.severidad] || 0) + 1;
    console.log(
        '  Resumen: ' +
            Object.entries(resumen)
                .map(([s, n]) => `${SEVERIDAD[s].etiqueta}=${n}`)
                .join('  ')
    );
}

// Código de salida ≠ 0 si hay hallazgos de severidad alta o media (útil en CI).
function exitCodePorHallazgos(reporte) {
    return reporte.hallazgos.some((f) => f.severidad === 'alta' || f.severidad === 'media') ? 1 : 0;
}

async function escanear(entrada) {
    const url = await validarObjetivo(entrada);
    const { statusCode, headers, body } = await descargar(url);
    return analizar(url, statusCode, headers, body);
}

// --- Modos de ejecución ----------------------------------------------------
async function modoInteractivo() {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let cerrado = false;
    rl.on('close', () => {
        cerrado = true;
    });
    rl.on('SIGINT', () => rl.close());
    const pregunta = (q) =>
        new Promise((res) => {
            if (cerrado) return res(null);
            rl.question(q, res);
        });

    try {
        for (;;) {
            const respuesta = await pregunta('Introduce la URL a analizar (o "salir"): ');
            if (respuesta === null) break;
            const entrada = respuesta.trim();
            if (!entrada || entrada.toLowerCase() === 'salir') break;
            try {
                imprimirReporte(await escanear(entrada));
            } catch (err) {
                console.error('Error:', err.message);
            }
            console.log('');
        }
    } finally {
        rl.close();
    }
}

async function modoCLI(urls, json) {
    const reportes = [];
    let salida = 0;
    for (const u of urls) {
        try {
            const reporte = await escanear(u);
            reportes.push(reporte);
            if (!json) imprimirReporte(reporte, process.stdout.isTTY);
            salida = Math.max(salida, exitCodePorHallazgos(reporte));
        } catch (err) {
            const reporte = { url: u, error: err.message };
            reportes.push(reporte);
            if (!json) console.error(`Error en ${u}: ${err.message}`);
            salida = Math.max(salida, 2);
        }
    }
    if (json) console.log(JSON.stringify(reportes.length === 1 ? reportes[0] : reportes, null, 2));
    return salida;
}

function ayuda() {
    console.log(`Analizador de Vulnerabilidades Web

Uso:
  node index.js                     Modo interactivo (pregunta URLs)
  node index.js <url> [<url>...]    Analiza una o varias URLs y termina
  node index.js --json <url>        Salida en formato JSON
  node index.js -h | --help         Muestra esta ayuda

Código de salida (modo CLI): 0 sin hallazgos altos/medios, 1 con ellos, 2 si hubo errores.`);
}

async function main() {
    const args = process.argv.slice(2);
    if (args.includes('-h') || args.includes('--help')) {
        ayuda();
        return;
    }
    const json = args.includes('--json');
    const urls = args.filter((a) => a !== '--json');

    if (urls.length === 0) {
        await modoInteractivo();
        return;
    }
    process.exitCode = await modoCLI(urls, json);
}

// Ejecuta solo si se invoca directamente; si se importa, expone las funciones
// puras para poder testearlas.
if (require.main === module) {
    main().catch((err) => {
        console.error('Error fatal:', err.message);
        process.exitCode = 2;
    });
}

module.exports = {
    esDireccionPrivada,
    analizarCabeceras,
    analizarXSS,
    analizarOfuscacion,
    analizar,
    exitCodePorHallazgos,
};
