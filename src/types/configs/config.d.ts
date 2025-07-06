export interface ProcessEnv {
  // Server
  NODE_ENV: 'development' | 'production';
  PORT: number;

  // Database
  DATABASE_LOCAL: string;
  DATABASE_ONLINE: string;
  DATABASE_PASSWORD_ONLINE: string;
  DATABASE_PASSWORD_ONLINE: string;
  NODE_REDIS_URL: string;
  NODE_REDIS_PORT: string;

  // Redis / Upstash
  REDIS_URL: string;
  UPSTASH_REDIS_REST_URL: string;
  UPSTASH_REDIS_REST_TOKEN: string;

  // Secrets & Encryption
  ACTIVATION_SECRET: string;
  CRYPTO_SECRET: string;
  HMAC_SECRET: string;
  EMAIL_CHANGE_SECRET: string;
  ALGORITHM: string;
  KEY_LENGTH: number;
  IV_LENGTH: number;

  // Auth Tokens
  ACCESS_TOKEN: string;
  REFRESH_TOKEN: string;
  ACCESS_TOKEN_EXPIRE: number | StringValue | undefined;
  REFRESH_TOKEN_EXPIRE: number | StringValue | undefined;

  // Email
  EMAIL_USERNAME: string;
  EMAIL_PASSWORD: string;
  EMAIL_HOST: string;
  EMAIL_PORT: number;
  EMAIL_FROM: string;

  // OAuth - Google
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;

  // OAuth - GitHub
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;

  // Cloudinary
  CLOUD_NAME: string;
  CLOUD_API_KEY: string;
  CLOUD_API_SECRET: string;
  CLOUDINARY_URL: string;

  // IPInfo
  IPINFO_KEY: string;

  // Client url
  CLIENT_ORIGIN: string;
  SHOP_ORIGIN: string;

  // Cookie secret
  COOKIE_SECRET: string;
}
