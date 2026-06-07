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

// Expresión regular para localizar etiquetas <script> en el HTML.
// NOTA: la presencia de <script> NO implica una vulnerabilidad de XSS por sí
// sola; es solo una señal a revisar manualmente.
const SCRIPT_PATTERN = /<\s*script\b[^>]*>/gi;

// --- Protección anti-SSRF --------------------------------------------------
// Bloquea destinos hacia rangos internos/privados para que la herramienta no
// pueda usarse para alcanzar metadatos de cloud o servicios internos.
function esDireccionPrivada(ip) {
    const tipo = net.isIP(ip);
    if (tipo === 4) {
        const o = ip.split('.').map(Number);
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
        const v = ip.toLowerCase();
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
function descargarHTML(url, redirecciones = 0) {
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
                        .then((u) => resolve(descargarHTML(u, redirecciones + 1)))
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

                resp.on('end', () => resolve(Buffer.concat(trozos).toString('utf8')));
                resp.on('error', reject);
            }
        );

        req.setTimeout(REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`Tiempo de espera agotado (${REQUEST_TIMEOUT_MS} ms)`));
        });
        req.on('error', reject);
    });
}

// --- Análisis del HTML -----------------------------------------------------
function analizarCodigoHTML(htmlContent) {
    const matches = htmlContent.match(SCRIPT_PATTERN);

    if (matches && matches.length > 0) {
        console.log('Se encontraron las siguientes etiquetas <script> a revisar:');
        matches.forEach((match, index) => {
            console.log(`  ${index + 1}: ${match}`);
        });
        console.log('(Recuerda: la presencia de <script> no implica XSS por sí sola.)');
    } else {
        console.log('No se encontraron etiquetas <script> en la página.');
    }
}

// --- Bucle interactivo (sin recursión que crezca la pila) ------------------
async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    let cerrado = false;
    rl.on('close', () => {
        cerrado = true;
    });
    // Cierre limpio con Ctrl+C.
    rl.on('SIGINT', () => rl.close());

    // Resuelve null si el flujo se cierra (EOF / Ctrl+C) en vez de lanzar.
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
                const url = await validarObjetivo(entrada);
                const html = await descargarHTML(url);
                analizarCodigoHTML(html);
            } catch (err) {
                console.error('Error:', err.message);
            }
            console.log('');
        }
    } finally {
        rl.close();
    }
}

main();
