FROM node:16-alpine

# Set environment variables
ENV NODE_ENV=production
ENV DATABASE_PASSWORD=super_secret_db_pass
ENV API_KEY=sk_prod_key_1234567890

# Install dependencies
WORKDIR /app
COPY package*.json ./
RUN npm install

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "server.js"]