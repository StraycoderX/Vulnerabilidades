'use strict';

const readline = require('readline');
const fs = require('fs');
const { escanear, exitCodePorHallazgos } = require('./src/engine');
const { rastrear } = require('./src/crawl');
const { mapearConcurrencia } = require('./src/pool');
const {
    imprimirReporte,
    huellasDeReportes,
    diffContraBaseline,
    aSARIF,
    aHTML,
} = require('./src/report');

// --- Modo interactivo ------------------------------------------------------
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

// --- Modo CLI no interactivo ----------------------------------------------
async function modoCLI(urls, opciones) {
    let salida = 0;
    let reportes;

    if (opciones.crawl > 0) {
        // Crawling: rastrea cada semilla (mismo origen) y agrega los reportes.
        reportes = [];
        for (const semilla of urls) {
            try {
                reportes.push(...(await rastrear(semilla, opciones)));
            } catch (err) {
                reportes.push({ url: semilla, error: err.message });
                salida = 2;
            }
        }
    } else {
        // Escaneo concurrente con límite, preservando el orden de las URLs.
        reportes = await mapearConcurrencia(urls, opciones.concurrencia, async (u) => {
            try {
                return await escanear(u, opciones);
            } catch (err) {
                salida = 2;
                return { url: u, error: err.message };
            }
        });
    }

    // Baseline / diff: reportar solo hallazgos nuevos frente al escaneo previo.
    let aMostrar = reportes;
    if (opciones.baseline) {
        if (!fs.existsSync(opciones.baseline)) {
            fs.writeFileSync(opciones.baseline, JSON.stringify({ huellas: huellasDeReportes(reportes) }, null, 2));
            if (!opciones.json && !opciones.sarif) {
                console.error(`Baseline creada en ${opciones.baseline} con ${huellasDeReportes(reportes).length} hallazgo(s). Próximos escaneos mostrarán solo lo nuevo.`);
            }
            aMostrar = [];
        } else {
            const baseline = JSON.parse(fs.readFileSync(opciones.baseline, 'utf8')).huellas || [];
            aMostrar = reportes.map((r) =>
                r.hallazgos ? { ...r, hallazgos: diffContraBaseline(r, baseline).nuevos } : r
            );
        }
        if (opciones.actualizarBaseline) {
            fs.writeFileSync(opciones.baseline, JSON.stringify({ huellas: huellasDeReportes(reportes) }, null, 2));
        }
    }

    // Salida.
    if (opciones.html) {
        console.log(aHTML(aMostrar));
    } else if (opciones.sarif) {
        console.log(JSON.stringify(aSARIF(aMostrar), null, 2));
    } else if (opciones.json) {
        console.log(JSON.stringify(aMostrar.length === 1 ? aMostrar[0] : aMostrar, null, 2));
    } else {
        for (const r of aMostrar) {
            if (r.error) console.error(`Error en ${r.url}: ${r.error}`);
            else imprimirReporte(r, process.stdout.isTTY);
        }
    }

    for (const r of aMostrar) {
        if (r.hallazgos) salida = Math.max(salida, exitCodePorHallazgos(r));
    }
    return salida;
}

function ayuda() {
    console.log(`Analizador de Vulnerabilidades Web

Uso:
  node index.js                          Modo interactivo (pregunta URLs)
  node index.js <url> [<url>...]         Analiza una o varias URLs y termina
  node index.js --json <url>             Salida en formato JSON
  node index.js --sarif <url>            Salida SARIF (GitHub Code Scanning)
  node index.js --baseline <f> <url>     Reporta solo hallazgos nuevos vs. baseline
  node index.js --baseline <f> --update-baseline <url>
                                         Igual, y actualiza la baseline al terminar
  node index.js --input urls.txt         Analiza las URLs de un fichero (una por línea)
  node index.js --concurrency N <urls>   Nº de escaneos en paralelo (por defecto 5)
  node index.js --html <url>             Salida como reporte HTML
  node index.js --crawl N [--max-pages M] <url>
                                         Rastrea el mismo origen hasta profundidad N
  node index.js --header "K: V" <url>    Cabecera personalizada (repetible)
  node index.js --cookie "k=v" <url>     Cookie de sesión (escaneo autenticado)
  node index.js --active --authorized <url?param=x>
                                         Sonda de XSS reflejado (¡solo con autorización!)
  node index.js -h | --help              Muestra esta ayuda

Código de salida (modo CLI): 0 sin hallazgos altos/medios, 1 con ellos, 2 si hubo errores.`);
}

async function main() {
    const args = process.argv.slice(2);
    if (args.includes('-h') || args.includes('--help')) {
        ayuda();
        return;
    }

    const opciones = {
        json: false, sarif: false, html: false,
        baseline: null, actualizarBaseline: false,
        concurrencia: 5, crawl: 0, maxPaginas: 20,
        active: false, authorized: false,
        headers: {}, cookie: null,
    };
    const urls = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === '--json') opciones.json = true;
        else if (a === '--sarif') opciones.sarif = true;
        else if (a === '--html') opciones.html = true;
        else if (a === '--update-baseline') opciones.actualizarBaseline = true;
        else if (a === '--baseline') opciones.baseline = args[++i];
        else if (a === '--concurrency') opciones.concurrencia = Math.max(1, Number(args[++i]) || 5);
        else if (a === '--crawl') opciones.crawl = Math.max(0, Number(args[++i]) || 0);
        else if (a === '--max-pages') opciones.maxPaginas = Math.max(1, Number(args[++i]) || 20);
        else if (a === '--active') opciones.active = true;
        else if (a === '--authorized') opciones.authorized = true;
        else if (a === '--cookie') opciones.cookie = args[++i];
        else if (a === '--header') {
            const h = args[++i] || '';
            const idx = h.indexOf(':');
            if (idx > 0) opciones.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
        } else if (a === '--input') {
            const fichero = args[++i];
            const lineas = fs.readFileSync(fichero, 'utf8')
                .split('\n')
                .map((l) => l.trim())
                .filter((l) => l && !l.startsWith('#'));
            urls.push(...lineas);
        } else urls.push(a);
    }

    if (opciones.active && !opciones.authorized) {
        console.error('El modo activo (--active) envía peticiones de prueba y solo debe usarse sobre objetivos\npropios o con autorización explícita. Añade --authorized para confirmarlo.');
        process.exitCode = 2;
        return;
    }

    if (urls.length === 0) {
        await modoInteractivo();
        return;
    }
    process.exitCode = await modoCLI(urls, opciones);
}

if (require.main === module) {
    main().catch((err) => {
        console.error('Error fatal:', err.message);
        process.exitCode = 2;
    });
}
