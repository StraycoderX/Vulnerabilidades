'use strict';

const { hallazgo } = require('./util');
const { parsearHTML } = require('../parser');

// Mini base de firmas estilo retire.js: detecta versiones de librerías JS con
// vulnerabilidades conocidas. Ampliable añadiendo entradas a esta lista.
// `vulnerableHasta`: la versión es vulnerable si es < a este valor (semver simple).
const FIRMAS = [
    { nombre: 'jQuery', regex: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, vulnerableHasta: '3.5.0', cve: 'XSS en htmlPrefilter (CVE-2020-11022/11023)' },
    { nombre: 'AngularJS', regex: /angular[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, vulnerableHasta: '1.8.0', cve: 'múltiples XSS/sandbox bypass' },
    { nombre: 'Bootstrap', regex: /bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i, vulnerableHasta: '3.4.1', cve: 'XSS en data-target (CVE-2018-14041 y rel.)' },
    { nombre: 'Lodash', regex: /lodash[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, vulnerableHasta: '4.17.21', cve: 'prototype pollution (CVE-2019-10744 y rel.)' },
    { nombre: 'Moment.js', regex: /moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, vulnerableHasta: '2.29.4', cve: 'ReDoS / path traversal (CVE-2022-31129)' },
];

// Compara dos versiones semver simples (x.y.z). Devuelve <0, 0 o >0.
function compararVersiones(a, b) {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) {
        if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
    }
    return 0;
}

function analizarLibrerias(ctx) {
    const dom = ctx.dom || parsearHTML(ctx.body || '');
    const hallazgos = [];
    const vistas = new Set();

    // Inspecciona el src de cada <script> en lugar de todo el HTML crudo.
    const fuentes = dom.elementos
        .filter((e) => e.tag === 'script' && e.attrs.src)
        .map((e) => e.attrs.src);

    for (const src of fuentes) {
        for (const firma of FIRMAS) {
            const m = src.match(firma.regex);
            if (!m) continue;
            const version = m[1];
            const clave = `${firma.nombre}@${version}`;
            if (vistas.has(clave)) continue;
            vistas.add(clave);
            if (compararVersiones(version, firma.vulnerableHasta) < 0) {
                hallazgos.push(hallazgo({
                    id: 'libreria-vulnerable',
                    severidad: 'media',
                    categoria: 'dependencias',
                    mensaje: `${firma.nombre} ${version} es vulnerable (< ${firma.vulnerableHasta})`,
                    detalle: firma.cve,
                    referencia: 'https://retirejs.github.io/retire.js/',
                }));
            }
        }
    }

    return hallazgos;
}

module.exports = { analizarLibrerias, compararVersiones };
