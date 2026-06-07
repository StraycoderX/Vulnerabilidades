'use strict';

// Tokenizador HTML ligero, sin dependencias. No es un parser DOM completo, pero
// recorre el HTML como una máquina de estados (respetando comillas y comentarios)
// y extrae cada elemento con su etiqueta y atributos, además del contenido de
// <script>/<style>. Es más preciso que aplicar expresiones regulares sueltas
// sobre el HTML crudo.

// Parsea la cadena de atributos de una etiqueta en un objeto { nombre: valor }.
function parsearAtributos(cadena) {
    const attrs = {};
    const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let m;
    while ((m = re.exec(cadena)) !== null) {
        if (!m[1]) continue;
        const nombre = m[1].toLowerCase();
        const valor = m[2] ?? m[3] ?? m[4] ?? '';
        attrs[nombre] = valor;
    }
    return attrs;
}

// Encuentra el índice del '>' que cierra la etiqueta abierta en `lt`,
// ignorando los '>' que aparezcan dentro de valores entrecomillados.
function finDeEtiqueta(html, lt) {
    let i = lt + 1;
    let comilla = null;
    while (i < html.length) {
        const c = html[i];
        if (comilla) {
            if (c === comilla) comilla = null;
        } else if (c === '"' || c === "'") {
            comilla = c;
        } else if (c === '>') {
            return i;
        }
        i++;
    }
    return -1;
}

// Devuelve { elementos: [{ tag, attrs, contenido }] }.
function parsearHTML(html) {
    const elementos = [];
    const n = html.length;
    let i = 0;

    while (i < n) {
        const lt = html.indexOf('<', i);
        if (lt < 0) break;

        // Comentarios.
        if (html.startsWith('<!--', lt)) {
            const fin = html.indexOf('-->', lt + 4);
            i = fin < 0 ? n : fin + 3;
            continue;
        }
        // Declaraciones (<!doctype ...>) y secciones especiales.
        if (html[lt + 1] === '!' || html[lt + 1] === '?') {
            const gt = html.indexOf('>', lt);
            i = gt < 0 ? n : gt + 1;
            continue;
        }

        const gt = finDeEtiqueta(html, lt);
        if (gt < 0) break;

        const interior = html.slice(lt + 1, gt);
        // Etiqueta de cierre: la ignoramos (el contenido de script ya se captura aparte).
        if (interior[0] === '/') {
            i = gt + 1;
            continue;
        }

        const mt = interior.match(/^([a-zA-Z][a-zA-Z0-9-]*)([\s\S]*)$/);
        if (!mt) {
            i = gt + 1;
            continue;
        }
        const tag = mt[1].toLowerCase();
        const attrs = parsearAtributos(mt[2]);
        let contenido = '';
        let siguiente = gt + 1;

        // El contenido de script/style es texto crudo (no se parsea como HTML).
        const autocierre = interior.trimEnd().endsWith('/');
        if ((tag === 'script' || tag === 'style') && !autocierre) {
            const cierre = new RegExp(`</\\s*${tag}\\s*>`, 'i');
            const resto = html.slice(gt + 1);
            const cm = resto.match(cierre);
            if (cm) {
                contenido = resto.slice(0, cm.index);
                siguiente = gt + 1 + cm.index + cm[0].length;
            } else {
                contenido = resto;
                siguiente = n;
            }
        }

        elementos.push({ tag, attrs, contenido });
        i = siguiente;
    }

    return { elementos };
}

module.exports = { parsearHTML, parsearAtributos };
