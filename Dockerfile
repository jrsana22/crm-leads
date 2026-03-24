FROM node:24-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN mkdir -p /app/data
VOLUME /app/data
EXPOSE 3000
CMD ["node", "--experimental-sqlite", "server.js"]
