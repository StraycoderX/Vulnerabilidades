'use strict';

const { SEVERIDAD, RESET } = require('./config');

// --- Reporte de consola ----------------------------------------------------
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

// --- Baseline / diff -------------------------------------------------------
// Huella estable de un hallazgo dentro de una URL, para comparar entre escaneos.
function huella(url, f) {
    return `${url}|${f.id}|${f.mensaje}`;
}

// Devuelve { nuevos, conocidos } comparando un reporte contra un conjunto de huellas.
function diffContraBaseline(reporte, baseline) {
    const conocidas = new Set(baseline);
    const nuevos = [];
    const conocidos = [];
    for (const f of reporte.hallazgos) {
        (conocidas.has(huella(reporte.url, f)) ? conocidos : nuevos).push(f);
    }
    return { nuevos, conocidos };
}

// Construye el conjunto de huellas a partir de uno o varios reportes.
function huellasDeReportes(reportes) {
    const set = [];
    for (const r of reportes) {
        if (!r.hallazgos) continue;
        for (const f of r.hallazgos) set.push(huella(r.url, f));
    }
    return set;
}

// --- SARIF (para GitHub Code Scanning) -------------------------------------
function aSARIF(reportes) {
    const reglasVistas = new Map();
    const results = [];

    for (const r of reportes) {
        if (!r.hallazgos) continue;
        for (const f of r.hallazgos) {
            if (!reglasVistas.has(f.id)) {
                reglasVistas.set(f.id, {
                    id: f.id,
                    name: f.id,
                    shortDescription: { text: f.mensaje },
                    helpUri: f.referencia || undefined,
                    defaultConfiguration: { level: SEVERIDAD[f.severidad].sarif },
                    properties: { category: f.categoria, severidad: f.severidad },
                });
            }
            results.push({
                ruleId: f.id,
                level: SEVERIDAD[f.severidad].sarif,
                message: { text: f.detalle ? `${f.mensaje} — ${f.detalle}` : f.mensaje },
                locations: [
                    { physicalLocation: { artifactLocation: { uri: r.url } } },
                ],
            });
        }
    }

    return {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'analizador-vulnerabilidades-web',
                        informationUri: 'https://github.com/StraycoderX/Vulnerabilidades',
                        version: '2.0.0',
                        rules: [...reglasVistas.values()],
                    },
                },
                results,
            },
        ],
    };
}

// --- Reporte HTML ----------------------------------------------------------
function escaparHTML(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function aHTML(reportes) {
    const colores = { alta: '#d32f2f', media: '#f57c00', baja: '#0288d1', info: '#757575' };
    const filas = [];
    for (const r of reportes) {
        if (r.error) {
            filas.push(`<tr><td>${escaparHTML(r.url)}</td><td colspan="3" class="err">Error: ${escaparHTML(r.error)}</td></tr>`);
            continue;
        }
        for (const f of r.hallazgos) {
            filas.push(
                `<tr>` +
                    `<td>${escaparHTML(r.url)}</td>` +
                    `<td><span class="sev" style="background:${colores[f.severidad]}">${SEVERIDAD[f.severidad].etiqueta}</span></td>` +
                    `<td>${escaparHTML(f.categoria)}</td>` +
                    `<td>${escaparHTML(f.mensaje)}${f.detalle ? `<br><small>${escaparHTML(f.detalle)}</small>` : ''}</td>` +
                    `</tr>`
            );
        }
    }
    return `<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Reporte de seguridad web</title>
<style>
body{font-family:system-ui,Arial,sans-serif;margin:2rem;color:#222}
h1{font-size:1.4rem} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top;font-size:.9rem}
th{background:#f5f5f5} .sev{color:#fff;padding:.1rem .5rem;border-radius:.3rem;font-size:.75rem}
.err{color:#d32f2f} small{color:#666}
</style></head><body>
<h1>Reporte de seguridad web</h1>
<p>${reportes.length} URL(s) analizada(s) · ${new Date().toISOString()}</p>
<table><thead><tr><th>URL</th><th>Severidad</th><th>Categoría</th><th>Hallazgo</th></tr></thead>
<tbody>${filas.join('\n') || '<tr><td colspan="4">Sin hallazgos.</td></tr>'}</tbody></table>
</body></html>`;
}

module.exports = {
    imprimirReporte,
    huella,
    huellasDeReportes,
    diffContraBaseline,
    aSARIF,
    aHTML,
};
