'use strict';

const { hallazgo } = require('./util');

const REF_TLS = 'https://owasp.org/www-project-transport-layer-protection/';

// Evalúa la información TLS recogida por src/tls.js (en ctx.tls). Si no hay datos
// (sitio http o fallo de conexión) no produce hallazgos.
function analizarTLS(ctx) {
    const t = ctx.tls;
    if (!t || t.error) return [];
    const hallazgos = [];

    const proto = (t.protocol || '').toUpperCase();
    if (['SSLV3', 'TLSV1', 'TLSV1.1'].includes(proto)) {
        hallazgos.push(hallazgo({
            id: 'tls-protocolo-obsoleto', severidad: 'alta', categoria: 'tls',
            mensaje: `Protocolo TLS obsoleto en uso: ${t.protocol}`,
            detalle: 'TLS 1.0/1.1 y SSLv3 están en desuso por inseguros; usa TLS 1.2+.',
            referencia: REF_TLS,
        }));
    }

    if (t.validTo) {
        const dias = Math.floor((Date.parse(t.validTo) - Date.now()) / 86400000);
        if (Number.isNaN(dias)) {
            // fecha no parseable: no reportamos
        } else if (dias < 0) {
            hallazgos.push(hallazgo({
                id: 'tls-cert-caducado', severidad: 'alta', categoria: 'tls',
                mensaje: `Certificado TLS caducado (venció hace ${-dias} día(s))`,
                detalle: `valid_to: ${t.validTo}`, referencia: REF_TLS,
            }));
        } else if (dias < 15) {
            hallazgos.push(hallazgo({
                id: 'tls-cert-por-caducar', severidad: 'media', categoria: 'tls',
                mensaje: `El certificado TLS caduca pronto (en ${dias} día(s))`,
                detalle: `valid_to: ${t.validTo}`, referencia: REF_TLS,
            }));
        }
    }

    return hallazgos;
}

module.exports = { analizarTLS };
