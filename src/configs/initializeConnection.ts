import cloudinary from './cloudinary';
import config from './config';
import db from './db';
import { nodeClient } from './redis';

// Initialize MongoDB connection
async function initializeMongoDB() {
  try {
    await db(config.DB);
    console.log('✅ Connected to MongoDB 🍃');
  } catch (error) {
    console.error('❌ MongoDB 🍃 Connection Error:', (error as Error).message);
    process.exit(1);
  }
}

// Initialize Redis connections
async function initializeRedis() {
  // Io Redis
  // const ioRedis = await ioClient.ping();
  // console.log('✅ Io Redis 🛠️  Connection Successful:', ioRedis);

  // Node Redis
  const nodeRedis = await nodeClient.connect();
  console.log('✅ Node Redis 🔗 Client Connection Successful', nodeRedis);

  // Io Redis
  // const upstashRedis = await upstashClient.ping();
  // console.log('✅ Upstash Redis 🛠️  Connection Successful:', upstashRedis);
}

// Initialize Cloudinary connection
async function initializeCloudinary() {
  // Check if Cloudinary is properly configured
  const result = await cloudinary.api.ping();
  console.log('✅ Cloudinary ☁️  Connection Successful:', result.status);
}

export { initializeCloudinary, initializeMongoDB, initializeRedis };
