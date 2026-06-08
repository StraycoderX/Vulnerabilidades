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
            try {
                resultados[i] = await fn(items[i], i);
            } catch (err) {
                // Un fallo en una tarea no debe tumbar todo el lote.
                resultados[i] = { error: err && err.message ? err.message : String(err) };
            }
        }
    }

    await Promise.all(Array.from({ length: n }, () => trabajador()));
    return resultados;
}

module.exports = { mapearConcurrencia };
