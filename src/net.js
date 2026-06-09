'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');
const { REQUEST_TIMEOUT_MS, MAX_TOTAL_MS, MAX_RESPONSE_BYTES, MAX_REDIRECTS } = require('./config');

// Agentes con keep-alive: reutilizan conexiones (clave al crawlear el mismo host).
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

// Cabeceras de petición por defecto. `Accept-Encoding: identity` evita que un
// servidor devuelva el cuerpo comprimido (que rompería el análisis del HTML).
const CABECERAS_BASE = {
    'User-Agent': 'AnalizadorVuln/2.2 (+https://github.com/StraycoderX/Vulnerabilidades)',
    'Accept-Encoding': 'identity',
    Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
};

const CABECERAS_SENSIBLES = /^(cookie|authorization|proxy-authorization)$/i;

// --- Protección anti-SSRF --------------------------------------------------
// Normaliza un IPv4 embebido en IPv6 (mapped/compatible), tanto en forma con
// puntos (::ffff:127.0.0.1) como hexadecimal (::ffff:7f00:1) — bypasses clásicos.
function ipv4Embebida(v) {
    v = v.toLowerCase();
    let m = v.match(/^::(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (m) return m[1];
    m = v.match(/:ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (m) {
        const a = parseInt(m[1], 16);
        const b = parseInt(m[2], 16);
        return `${(a >> 8) & 255}.${a & 255}.${(b >> 8) & 255}.${b & 255}`;
    }
    return null;
}

// Bloquea destinos hacia rangos internos/privados/reservados para que la
// herramienta no pueda usarse para alcanzar metadatos de cloud o infra interna.
function esDireccionPrivada(ip) {
    let dir = ipv4Embebida(ip) || ip;

    const tipo = net.isIP(dir);
    if (tipo === 4) {
        const o = dir.split('.').map(Number);
        return (
            o[0] === 0 ||
            o[0] === 10 ||
            o[0] === 127 ||
            (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || // CGNAT 100.64/10
            (o[0] === 169 && o[1] === 254) || // link-local / metadata cloud
            (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
            (o[0] === 192 && o[1] === 0 && o[2] === 0) || // 192.0.0.0/24
            (o[0] === 192 && o[1] === 168) ||
            (o[0] === 198 && (o[1] === 18 || o[1] === 19)) || // benchmark 198.18/15
            o[0] >= 224 // multicast (224/4) + reservado (240/4) + broadcast
        );
    }
    if (tipo === 6) {
        const v = dir.toLowerCase();
        return (
            v === '::1' || // loopback
            v === '::' ||
            v.startsWith('fc') || // unique local fc00::/7
            v.startsWith('fd') ||
            v.startsWith('fe80') || // link-local
            v.startsWith('ff') // multicast ff00::/8
        );
    }
    return false;
}

// Excepción SOLO para tests de integración: requiere NODE_ENV=test y la variable
// explícita. Doble condición para que nunca se active por accidente en producción.
function loopbackPermitidoEnPruebas(address) {
    if (process.env.NODE_ENV !== 'test' || process.env.VULN_TEST_ALLOW_LOOPBACK !== '1') return false;
    const v4 = ipv4Embebida(address) || address;
    return v4 === '127.0.0.1' || address === '::1';
}

// Valida el esquema y resuelve el host para rechazar objetivos internos.
// Devuelve { url, address, family } con la IP ya validada para fijar la conexión.
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

    const { address, family } = await dns.lookup(url.hostname);
    if (esDireccionPrivada(address) && !loopbackPermitidoEnPruebas(address)) {
        throw new Error(`Destino bloqueado por seguridad (dirección interna/privada: ${address})`);
    }

    return { url, address, family };
}

// Devuelve un `lookup` que siempre resuelve a la IP ya validada (anti DNS-rebinding).
// Honra la opción `all` (la usa autoSelectFamily/Happy Eyeballs desde Node 20):
// con `all:true` el callback debe devolver un array [{address, family}].
function lookupFijo(address, family) {
    const fam = family || (address.includes(':') ? 6 : 4);
    return (hostname, options, callback) => {
        const cb = typeof options === 'function' ? options : callback;
        const opts = typeof options === 'function' ? {} : options || {};
        if (opts.all) cb(null, [{ address, family: fam }]);
        else cb(null, address, fam);
    };
}

// Extrae información TLS de un socket ya conectado (sin abrir conexión extra).
function tlsDesdeSocket(socket) {
    if (!socket || typeof socket.getPeerCertificate !== 'function') return null;
    const cert = socket.getPeerCertificate() || {};
    return {
        protocol: typeof socket.getProtocol === 'function' ? socket.getProtocol() : null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        error: null,
    };
}

// --- Descarga del HTML con controles de seguridad --------------------------
// Devuelve { statusCode, headers, body, url, tls } donde `url` es la URL final
// (tras redirecciones) y `tls` la info del certificado (en https con cert válido).
function descargar(target, extra = {}, redirecciones = 0) {
    const { url, address, family } = target;
    return new Promise((resolve, reject) => {
        const esHttps = url.protocol === 'https:';
        const cliente = esHttps ? https : http;

        const opciones = {
            rejectUnauthorized: true,
            lookup: lookupFijo(address, family),
            agent: esHttps ? httpsAgent : httpAgent,
            headers: { ...CABECERAS_BASE, ...(extra.headers || {}) },
        };

        let cerrado = false;
        const limpiar = () => {
            clearTimeout(deadline);
        };
        const fin = (fn, arg) => {
            if (cerrado) return;
            cerrado = true;
            limpiar();
            fn(arg);
        };
        // Deadline absoluto: corta la conexión aunque siga goteando bytes.
        const deadline = setTimeout(
            () => req.destroy(new Error(`Deadline total agotado (${MAX_TOTAL_MS} ms)`)),
            MAX_TOTAL_MS
        );

        const req = cliente.get(url, opciones, (resp) => {
            const { statusCode, headers } = resp;

            // Redirecciones controladas (con revalidación anti-SSRF).
            if (statusCode >= 300 && statusCode < 400 && headers.location) {
                resp.resume(); // descarta el cuerpo
                if (extra.noFollow) {
                    return fin(resolve, { statusCode, headers, body: '', url, tls: null });
                }
                if (redirecciones >= MAX_REDIRECTS) {
                    return fin(reject, new Error('Demasiadas redirecciones'));
                }
                let destino;
                try {
                    destino = new URL(headers.location, url);
                } catch {
                    return fin(reject, new Error('Location de redirección inválido'));
                }
                // Al cambiar de origen, NO reenviar credenciales (anti fuga).
                let extraSig = extra;
                if (destino.origin !== url.origin) {
                    const limpias = {};
                    for (const [k, val] of Object.entries(extra.headers || {})) {
                        if (!CABECERAS_SENSIBLES.test(k)) limpias[k] = val;
                    }
                    extraSig = { ...extra, headers: limpias };
                }
                limpiar();
                cerrado = true;
                return validarObjetivo(destino.href)
                    .then((t) => resolve(descargar(t, extraSig, redirecciones + 1)))
                    .catch(reject);
            }

            if (statusCode < 200 || statusCode >= 300) {
                resp.resume();
                return fin(reject, new Error(`Respuesta HTTP ${statusCode}`));
            }

            const tls = esHttps ? tlsDesdeSocket(resp.socket) : null;
            const trozos = [];
            let total = 0;

            resp.on('data', (chunk) => {
                total += chunk.length;
                if (total > MAX_RESPONSE_BYTES) {
                    req.destroy();
                    return fin(reject, new Error(`Respuesta demasiado grande (> ${MAX_RESPONSE_BYTES} bytes)`));
                }
                trozos.push(chunk);
            });

            resp.on('end', () =>
                fin(resolve, { statusCode, headers, body: Buffer.concat(trozos).toString('utf8'), url, tls })
            );
            resp.on('error', (e) => fin(reject, e));
        });

        req.setTimeout(REQUEST_TIMEOUT_MS, () => {
            req.destroy(new Error(`Tiempo de espera agotado (${REQUEST_TIMEOUT_MS} ms)`));
        });
        req.on('error', (e) => fin(reject, e));
    });
}

module.exports = { esDireccionPrivada, validarObjetivo, descargar, lookupFijo, tlsDesdeSocket };
