FROM node:22-bookworm-slim
ENV PUPPETEER_SKIP_DOWNLOAD=true
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_ENV=production
EXPOSE 3782
CMD ["node", "src/server.js"]
