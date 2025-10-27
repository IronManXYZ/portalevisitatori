FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN mkdir -p /app/data /app/backups

EXPOSE 3000

ENV DATA_DIR=/app/data

CMD ["npm", "start"]