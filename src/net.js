'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');
const { REQUEST_TIMEOUT_MS, MAX_RESPONSE_BYTES, MAX_REDIRECTS } = require('./config');

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
            v === '::1' || // loopback
            v.startsWith('fc') || // unique local
            v.startsWith('fd') ||
            v.startsWith('fe80') || // link-local
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

        const req = cliente.get(url, { rejectUnauthorized: true }, (resp) => {
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
                    return reject(new Error(`Respuesta demasiado grande (> ${MAX_RESPONSE_BYTES} bytes)`));
                }
                trozos.push(chunk);
            });

            resp.on('end', () =>
                resolve({ statusCode, headers, body: Buffer.concat(trozos).toString('utf8') })
            );
            resp.on('error', reject);
        });

        req.setTimeout(REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`Tiempo de espera agotado (${REQUEST_TIMEOUT_MS} ms)`));
        });
        req.on('error', reject);
    });
}

module.exports = { esDireccionPrivada, validarObjetivo, descargar };
