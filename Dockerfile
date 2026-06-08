# Imagen mínima: el analizador no tiene dependencias de ejecución.
FROM node:20-alpine

WORKDIR /app
COPY package.json index.js ./
COPY src ./src

# El usuario node no-root para no ejecutar como root.
USER node

ENTRYPOINT ["node", "/app/index.js"]
