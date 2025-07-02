import { Redis } from '@upstash/redis';
import IoRedis from 'ioredis';
import { createClient } from 'redis';
import config from './config';

export const nodeClient = createClient({ url: config.REDIS_URL });

export const ioClient = new IoRedis(config.REDIS_URL);

export const upstashClient = new Redis({
  url: config.UPSTASH_REDIS_REST_URL,
  token: config.UPSTASH_REDIS_REST_TOKEN,
});

nodeClient.on('error', function (err) {
  throw err;
});
