'use strict';

// Registro de reglas. Cada regla es una función (ctx) => hallazgo[].
// Para añadir una nueva comprobación basta con crear el módulo y registrarlo aquí.
const { analizarCabeceras } = require('./headers');
const { analizarXSS } = require('./xss');
const { analizarOfuscacion } = require('./obfuscation');
const { analizarLibrerias } = require('./libraries');
const { analizarTLS } = require('./tls');
const { analizarActivo } = require('./active');
const { analizarHeadless } = require('./headless');

const reglas = [
    analizarCabeceras,
    analizarXSS,
    analizarOfuscacion,
    analizarLibrerias,
    analizarTLS,
    analizarActivo,
    analizarHeadless,
];

module.exports = { reglas };
