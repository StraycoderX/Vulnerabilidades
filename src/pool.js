'use strict';

// Aplica `fn` a cada elemento con un máximo de `limite` tareas en vuelo a la vez.
// Preserva el orden de los resultados respecto a la entrada.
async function mapearConcurrencia(items, limite, fn) {
    const resultados = new Array(items.length);
    let siguiente = 0;
    const n = Math.max(1, Math.min(limite, items.length));

    async function trabajador() {
        while (siguiente < items.length) {
            const i = siguiente++;
            resultados[i] = await fn(items[i], i);
        }
    }

    await Promise.all(Array.from({ length: n }, () => trabajador()));
    return resultados;
}

module.exports = { mapearConcurrencia };
