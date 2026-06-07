'use strict';

// Registro de reglas. Cada regla es una función (ctx) => hallazgo[].
// Para añadir una nueva comprobación basta con crear el módulo y registrarlo aquí.
const { analizarCabeceras } = require('./headers');
const { analizarXSS } = require('./xss');
const { analizarOfuscacion } = require('./obfuscation');

const reglas = [analizarCabeceras, analizarXSS, analizarOfuscacion];

module.exports = { reglas };
