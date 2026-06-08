'use strict';

const { URL } = require('url');
const { escanearDetallado } = require('./engine');
const { mapearConcurrencia } = require('./pool');

// Extrae enlaces del mismo origen a partir del DOM tokenizado.
function extraerEnlacesMismoOrigen(dom, base) {
    const enlaces = new Set();
    for (const el of dom.elementos) {
        if (el.tag !== 'a' || !el.attrs.href) continue;
        let u;
        try {
            u = new URL(el.attrs.href, base);
        } catch {
            continue;
        }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
        if (u.origin !== base.origin) continue;
        u.hash = '';
        enlaces.add(u.href);
    }
    return [...enlaces];
}

// Rastrea desde una URL semilla, mismo origen, por niveles (BFS) hasta `profundidad`
// y un máximo de `maxPaginas`, escaneando cada página con concurrencia limitada.
// Devuelve un array de reportes.
async function rastrear(semilla, opciones = {}) {
    const profundidad = opciones.crawl || 0;
    const maxPaginas = opciones.maxPaginas || 20;
    const concurrencia = opciones.concurrencia || 5;

    const visitadas = new Set();
    const reportes = [];
    let nivelActual = [semilla];
    visitadas.add(semilla);

    for (let prof = 0; prof <= profundidad && nivelActual.length > 0; prof++) {
        const restante = maxPaginas - reportes.length;
        if (restante <= 0) break;
        const aEscanear = nivelActual.slice(0, restante);

        const resultados = await mapearConcurrencia(aEscanear, concurrencia, async (u) => {
            try {
                return await escanearDetallado(u, opciones);
            } catch (err) {
                return { reporte: { url: u, error: err.message }, dom: null };
            }
        });

        const siguiente = new Set();
        for (const r of resultados) {
            reportes.push(r.reporte);
            if (prof < profundidad && r.dom && r.url) {
                for (const enlace of extraerEnlacesMismoOrigen(r.dom, r.url)) {
                    if (!visitadas.has(enlace)) {
                        visitadas.add(enlace);
                        siguiente.add(enlace);
                    }
                }
            }
        }
        nivelActual = [...siguiente];
    }

    return reportes;
}

module.exports = { rastrear, extraerEnlacesMismoOrigen };
