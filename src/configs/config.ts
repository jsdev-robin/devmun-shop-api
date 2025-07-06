import dotenv from 'dotenv';
import { ProcessEnv } from '../types/configs/config';

dotenv.config({ path: './.env' });

function validateEnvVariables(env: ProcessEnv): void {
  const requiredVars: Array<keyof ProcessEnv> = [
    'NODE_ENV',
    'PORT',

    'DATABASE_LOCAL',
    'DATABASE_ONLINE',
    'DATABASE_PASSWORD_ONLINE',

    'REDIS_URL',
    'UPSTASH_REDIS_REST_URL',
    'UPSTASH_REDIS_REST_TOKEN',
    'NODE_REDIS_URL',
    'NODE_REDIS_PORT',

    'ACTIVATION_SECRET',
    'CRYPTO_SECRET',
    'HMAC_SECRET',
    'EMAIL_CHANGE_SECRET',
    'ALGORITHM',
    'KEY_LENGTH',
    'IV_LENGTH',

    'ACCESS_TOKEN',
    'REFRESH_TOKEN',
    'ACCESS_TOKEN_EXPIRE',
    'REFRESH_TOKEN_EXPIRE',

    'EMAIL_USERNAME',
    'EMAIL_PASSWORD',
    'EMAIL_HOST',
    'EMAIL_PORT',
    'EMAIL_FROM',

    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',

    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',

    'CLOUD_NAME',
    'CLOUD_API_KEY',
    'CLOUD_API_SECRET',
    'CLOUDINARY_URL',

    'IPINFO_KEY',

    'CLIENT_ORIGIN',
    'SHOP_ORIGIN',

    'COOKIE_SECRET',
  ];

  const missingVars = requiredVars.filter(
    (key) => env[key] === undefined || env[key] === ''
  );

  if (missingVars.length > 0) {
    console.error(`Missing environment variables: ${missingVars.join(', ')}`);
    process.exit(1);
  }
}

const env = process.env as unknown as ProcessEnv;
validateEnvVariables(env);

const {
  NODE_ENV = 'development',
  PORT = '8080',

  DATABASE_LOCAL = '',
  DATABASE_ONLINE = '',
  DATABASE_PASSWORD_ONLINE = '',

  REDIS_URL = '',
  UPSTASH_REDIS_REST_URL = '',
  UPSTASH_REDIS_REST_TOKEN = '',
  NODE_REDIS_URL = '',
  NODE_REDIS_PORT = '',

  ACTIVATION_SECRET = '',
  CRYPTO_SECRET = '',
  HMAC_SECRET = '',
  EMAIL_CHANGE_SECRET = '',
  ALGORITHM = '',
  KEY_LENGTH = '',
  IV_LENGTH = '',

  ACCESS_TOKEN = '',
  REFRESH_TOKEN = '',
  ACCESS_TOKEN_EXPIRE = '',
  REFRESH_TOKEN_EXPIRE = '',

  EMAIL_USERNAME = '',
  EMAIL_PASSWORD = '',
  EMAIL_HOST = '',
  EMAIL_PORT = '',
  EMAIL_FROM = '',

  GOOGLE_CLIENT_ID = '',
  GOOGLE_CLIENT_SECRET = '',

  GITHUB_CLIENT_ID = '',
  GITHUB_CLIENT_SECRET = '',

  CLOUD_NAME = '',
  CLOUD_API_KEY = '',
  CLOUD_API_SECRET = '',
  CLOUDINARY_URL = '',

  IPINFO_KEY = '',

  CLIENT_ORIGIN = '',
  SHOP_ORIGIN = '',

  COOKIE_SECRET = '',
} = env;

const ISPRODUCTION = NODE_ENV === 'production';
const DB = ISPRODUCTION
  ? DATABASE_ONLINE.replace('<db_password>', DATABASE_PASSWORD_ONLINE)
  : DATABASE_LOCAL;

const config = {
  NODE_ENV,
  PORT,

  DATABASE_LOCAL,
  DATABASE_ONLINE,
  DATABASE_PASSWORD_ONLINE,

  REDIS_URL,
  UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN,
  NODE_REDIS_URL,
  NODE_REDIS_PORT,

  ACTIVATION_SECRET,
  CRYPTO_SECRET,
  HMAC_SECRET,
  EMAIL_CHANGE_SECRET,
  ALGORITHM,
  KEY_LENGTH,
  IV_LENGTH,

  ACCESS_TOKEN,
  REFRESH_TOKEN,
  ACCESS_TOKEN_EXPIRE,
  REFRESH_TOKEN_EXPIRE,

  EMAIL_USERNAME,
  EMAIL_PASSWORD,
  EMAIL_HOST,
  EMAIL_PORT,
  EMAIL_FROM,

  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,

  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,

  CLOUD_NAME,
  CLOUD_API_KEY,
  CLOUD_API_SECRET,
  CLOUDINARY_URL,

  IPINFO_KEY,

  CLIENT_ORIGIN,
  SHOP_ORIGIN,

  COOKIE_SECRET,

  ISPRODUCTION,
  DB,
};

export default config;
