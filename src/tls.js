'use strict';

const tls = require('tls');
const { REQUEST_TIMEOUT_MS } = require('./config');

// Inspecciona la conexión TLS de un objetivo https ya validado. Usa la IP fijada
// (anti DNS-rebinding) y `rejectUnauthorized: false` SOLO para poder leer y
// reportar certificados caducados/inválidos (la descarga del HTML sí los rechaza).
// Devuelve { protocol, validTo, validFrom, error }.
function inspeccionarTLS(target) {
    const { url, address, family } = target;
    const host = url.hostname;
    const port = url.port ? Number(url.port) : 443;

    return new Promise((resolve) => {
        let resuelto = false;
        const terminar = (valor) => {
            if (resuelto) return;
            resuelto = true;
            resolve(valor);
        };

        const socket = tls.connect(
            {
                host: address || host,
                port,
                servername: host, // SNI con el host real, aunque conectemos por IP
                rejectUnauthorized: false,
                lookup: (h, o, cb) => {
                    const f = typeof o === 'function' ? o : cb;
                    f(null, address || host, family || 4);
                },
            },
            () => {
                const cert = socket.getPeerCertificate();
                terminar({
                    protocol: socket.getProtocol(),
                    validFrom: cert && cert.valid_from ? cert.valid_from : null,
                    validTo: cert && cert.valid_to ? cert.valid_to : null,
                    error: null,
                });
                socket.end();
            }
        );

        socket.setTimeout(REQUEST_TIMEOUT_MS, () => {
            socket.destroy();
            terminar({ error: 'timeout' });
        });
        socket.on('error', (e) => terminar({ error: e.message }));
    });
}

module.exports = { inspeccionarTLS };
