import crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { RateLimiterMemory } from 'rate-limiter-flexible';

// Define honeypot paths here
const honeypotPaths = [
  // Common admin traps
  '/v1/admin',
  '/v1/admin/login',
  '/v1/admin/logout',
  '/v1/admin/panel',
  '/v1/admin/dashboard',
  '/v1/admin/delete',
  '/v1/admin/deleteAll',
  '/v1/admin/remove',
  '/v1/admin/removeAll',
  '/v1/admin/config',
  '/v1/admin/env',
  '/v1/admin/root',
  '/v1/admin/root/login',
  '/v1/admin/console',
  '/v1/admin/settings',
  '/v1/admin/hidden',
  '/v1/admin/secret',
  '/v1/admin123',
  '/v1/adminAccess',
  '/v1/admin_backup',
  '/v1/admin_database',

  // API-based traps
  '/v1/api/admin',
  '/v1/api/admin/deleteAllUsers',
  '/v1/api/admin/removeAllData',
  '/v1/api/admin/shutdownNow',
  '/v1/api/sudo/rootAccess',
  '/v1/api/superuser',
  '/v1/api/su',
  '/v1/api/hidden',
  '/v1/api/removeUsers',
  '/v1/api/clearDatabase',
  '/v1/api/deleteSite',
  '/v1/api/disable',
  '/v1/api/key',
  '/v1/api/token',
  '/v1/api/internal',
  '/v1/api/internal/update',
  '/v1/api/secret',
  '/v1/api/root',
  '/v1/api/debug',
  '/v1/api/auth/root',
  '/v1/api/auth/dev',
  '/v1/api/auth/hack',
  '/v1/api/kill-switch',
  '/v1/api/drop',

  // Root-level traps
  '/v1/root',
  '/v1/root/access',
  '/v1/root/login',
  '/v1/root/delete',
  '/v1/root/remove',
  '/v1/root/drop',
  '/v1/root/shutdown',
  '/v1/root/admin',
  '/v1/root/root',

  // Config/env traps
  '/v1/.env',
  '/v1/.git',
  '/v1/config.yml',
  '/v1/config.json',
  '/v1/settings.py',
  '/v1/settings.env',
  '/v1/.dockerignore',
  '/v1/Dockerfile',
  '/v1/server.js',
  '/v1/database.json',
  '/v1/env',
  '/v1/config',
  '/v1/backup/config',

  // Hidden/obscure route traps
  '/v1/hidden',
  '/v1/hidden/console',
  '/v1/hidden/debug',
  '/v1/hidden/admin',
  '/v1/secret',
  '/v1/secret/login',
  '/v1/secret/config',
  '/v1/secret/keys',
  '/v1/super/secret',
  '/v1/superuser',
  '/v1/debug',
  '/v1/debug/console',
  '/v1/debug/logs',
  '/v1/internal',
  '/v1/internal/logs',
  '/v1/internal/debug',

  // Fake login routes
  '/v1/login/admin',
  '/v1/login/dev',
  '/v1/login/super',
  '/v1/login/debug',
  '/v1/login/hidden',
  '/v1/login/hack',
  '/v1/logout/admin',
  '/v1/logout/dev',

  // Dangerous sounding actions
  '/v1/nuke',
  '/v1/kill',
  '/v1/wipe',
  '/v1/drop',
  '/v1/delete',
  '/v1/destroy',
  '/v1/format',
  '/v1/explode',
  '/v1/shutdown',
  '/v1/shutdown/system',
  '/v1/shutdown/app',
  '/v1/shutdown/now',

  // Database-related traps
  '/v1/database',
  '/v1/database/delete',
  '/v1/database/clear',
  '/v1/database/dump',
  '/v1/database/backup',
  '/v1/database/kill',
  '/v1/db',
  '/v1/db/remove',
  '/v1/db/clear',
  '/v1/db/drop',

  // Logs/info
  '/v1/logs',
  '/v1/logs/system',
  '/v1/logs/error',
  '/v1/system/info',
  '/v1/system/stats',
  '/v1/system/health',

  // WordPress / CMS guessing
  '/v1/wp-login.php',
  '/v1/wp-admin',
  '/v1/wp-content/debug.log',
  '/v1/wp-config.php',
  '/v1/wordpress/wp-login.php',
  '/v1/wordpress/wp-admin',

  // Laravel / PHP trap
  '/v1/.env.backup',
  '/v1/.env.local',
  '/v1/.env.production',
  '/v1/storage/logs/laravel.log',
  '/v1/.git/config',
  '/v1/public/storage',
  '/v1/vendor/phpunit',

  // Developer panel guessing
  '/v1/dev',
  '/v1/dev/api',
  '/v1/dev/console',
  '/v1/dev/env',
  '/v1/dev/health',
  '/v1/dev/status',
  '/v1/dev/monitor',
  '/v1/dev/debug',

  // Testing / sandbox routes
  '/v1/test',
  '/v1/test/api',
  '/v1/test/removeAll',
  '/v1/test/deleteEverything',
  '/v1/sandbox',
  '/v1/staging',
  '/v1/staging/remove',
  '/v1/demo/login',

  // Security bypass attempts
  '/v1/secure/bypass',
  '/v1/auth/bypass',
  '/v1/auth/force-login',
  '/v1/login/backdoor',
  '/v1/login/as-admin',
  '/v1/login2',
  '/v1/login3',
  '/v1/.well-known/security.txt',
  '/v1/.well-known/change-password',

  // Backup / zip download attempts
  '/v1/backup.zip',
  '/v1/site.zip',
  '/v1/source.zip',
  '/v1/database.sql',
  '/v1/db.sql',
  '/v1/dump.sql',
  '/v1/export.sql',
  '/v1/user.sql',
  '/v1/config.bak',
  '/v1/config.old',
  '/v1/config.php.old',
  '/v1/backup.tar.gz',

  // Version-based access
  '/v1/api/v0',
  '/v1/api/v0.1',
  '/v1/api/v1/private',
  '/v1/api/v1/hidden',
  '/v1/api/v1alpha',
  '/v1/api/v2-beta',
  '/v1/api/v99',

  // Random guessing
  '/v1/node_modules',
  '/v1/yarn.lock',
  '/v1/package-lock.json',
  '/v1/package.json',
  '/v1/src',
  '/v1/app.js',
  '/v1/index.js',
  '/v1/index.php',
  '/v1/cpanel',
  '/v1/ftp',
  '/v1/phpinfo.php',
  '/v1/info.php',
  '/v1/api/fake',
  '/v1/user/export',
  '/v1/admin/export', // Node.js / Express environment & files
  '/v1/.env',
  '/v1/.env.local',
  '/v1/.env.production',
  '/v1/.env.development',
  '/v1/.git/config',
  '/v1/.npmrc',
  '/v1/.nvmrc',
  '/v1/yarn.lock',
  '/v1/package-lock.json',
  '/v1/package.json',
  '/v1/tsconfig.json',
  '/v1/jsconfig.json',
  '/v1/.babelrc',
  '/v1/.eslintrc',
  '/v1/.prettierrc',
  '/v1/.dockerignore',

  // Express internal trap
  '/v1/express',
  '/v1/express/init',
  '/v1/express/router',
  '/v1/express/server',
  '/v1/app',
  '/v1/app.js',
  '/v1/server.js',
  '/v1/src/server.js',
  '/v1/src/app.js',

  // Dev endpoints often left open
  '/v1/dev',
  '/v1/dev/api',
  '/v1/dev/status',
  '/v1/dev/health',
  '/v1/dev/info',
  '/v1/dev/logs',
  '/v1/dev/errors',

  // Token/session leak attempts
  '/v1/auth/session',
  '/v1/auth/token',
  '/v1/auth/token/refresh',
  '/v1/auth/dev',
  '/v1/api/token',
  '/v1/api/token/dev',
  '/v1/internal/token',
  '/v1/.session',
  '/v1/.session.json',

  // Debug-related
  '/v1/debug',
  '/v1/debug/logs',
  '/v1/debug/errors',
  '/v1/debug/config',
  '/v1/debug/env',
  '/v1/debug/console',
  '/v1/debug/db',
  '/v1/api/debug',

  // Monitoring traps
  '/v1/metrics',
  '/v1/health',
  '/v1/healthcheck',
  '/v1/status',
  '/v1/info',
  '/v1/system/status',
  '/v1/system/info',

  // Hidden modules/assets
  '/v1/node_modules',
  '/v1/vendor',
  '/v1/build',
  '/v1/dist',
  '/v1/static',
  '/v1/static/js/bundle.js',

  // API versioning abuse
  '/v1/api/v999',
  '/v1/api/vNext',
  '/v1/api/vTest',
  '/v1/api/legacy',
  '/v1/api/devtools', // API Gateway/Management Traps
  '/v1/gateway',
  '/v1/gateway/admin',
  '/v1/api-gateway',
  '/v1/apigateway',
  '/v1/api/management',
  '/v1/api/manager',
  '/v1/api/control',
  '/v1/api/controller',

  // GraphQL Traps
  '/v1/graphql',
  '/v1/graphql/admin',
  '/v1/graphql/console',
  '/v1/graphiql',
  '/v1/playground',
  '/v1/altair',
  '/v1/graphql/schema',
  '/v1/graphql/introspection',
  '/v1/graphql/auth',
  '/v1/gql',
  '/v1/gql/admin',

  // Kubernetes/Cloud Traps
  '/v1/k8s',
  '/v1/kubernetes',
  '/v1/kube',
  '/v1/helm',
  '/v1/aws',
  '/v1/aws/s3',
  '/v1/aws/credentials',
  '/v1/gcp',
  '/v1/azure',
  '/v1/cloud',
  '/v1/cloud/metadata',
  '/v1/cloud/init',

  // CI/CD Traps
  '/v1/jenkins',
  '/v1/gitlab',
  '/v1/github',
  '/v1/bitbucket',
  '/v1/circleci',
  '/v1/travis',
  '/v1/actions',
  '/v1/ci',
  '/v1/cd',
  '/v1/ci-cd',
  '/v1/pipeline',

  // Microservice Traps
  '/v1/services',
  '/v1/services/admin',
  '/v1/microservices',
  '/v1/registry',
  '/v1/discovery',
  '/v1/service-registry',
  '/v1/eureka',
  '/v1/consul',
  '/v1/zipkin',

  // New Framework-Specific Traps
  '/v1/_next',
  '/v1/_next/static',
  '/v1/_nuxt',
  '/v1/_nuxt/config',
  '/v1/.svelte',
  '/v1/.svelte-kit',
  '/v1/remix',
  '/v1/astro',
  '/v1/qwik',
  '/v1/solid',

  // API Key/Secret Traps
  '/v1/keys',
  '/v1/keys/all',
  '/v1/keys/list',
  '/v1/secrets',
  '/v1/secrets/all',
  '/v1/secrets/list',
  '/v1/credentials',
  '/v1/credentials/all',
  '/v1/tokens',
  '/v1/tokens/all',
  '/v1/jwks',
  '/v1/jwks.json',

  // OAuth/SAML Traps
  '/v1/oauth',
  '/v1/oauth2',
  '/v1/saml',
  '/v1/openid',
  '/v1/auth/oauth',
  '/v1/auth/saml',
  '/v1/auth/openid',
  '/v1/.well-known/oauth-authorization-server',
  '/v1/.well-known/openid-configuration',

  // WebSocket Traps
  '/v1/ws',
  '/v1/ws/admin',
  '/v1/websocket',
  '/v1/socket.io',
  '/v1/socket.io/admin',
  '/v1/sockjs',
  '/v1/sockjs/info',

  // New Database Traps
  '/v1/mongo',
  '/v1/mongodb',
  '/v1/postgres',
  '/v1/mysql',
  '/v1/redis',
  '/v1/elasticsearch',
  '/v1/meilisearch',
  '/v1/arangodb',
  '/v1/neo4j',
  '/v1/couchdb',
  '/v1/dynamodb',
  '/v1/cassandra',

  // AI/ML Service Traps
  '/v1/ai',
  '/v1/ml',
  '/v1/model',
  '/v1/models',
  '/v1/llm',
  '/v1/openai',
  '/v1/huggingface',
  '/v1/tensorflow',
  '/v1/pytorch',
  '/v1/jupyter',
  '/v1/colab',

  // IoT/Device Traps
  '/v1/iot',
  '/v1/devices',
  '/v1/device/list',
  '/v1/sensors',
  '/v1/telemetry',
  '/v1/mqtt',
  '/v1/coap',
  '/v1/opcua',

  // Financial Traps
  '/v1/payment',
  '/v1/payments',
  '/v1/transaction',
  '/v1/transactions',
  '/v1/billing',
  '/v1/invoice',
  '/v1/invoices',
  '/v1/subscription',
  '/v1/subscriptions',
  '/v1/refund',
  '/v1/refunds',

  // Special Admin Traps
  '/v1/superadmin',
  '/v1/super-admin',
  '/v1/master',
  '/v1/owner',
  '/v1/systemadmin',
  '/v1/sysadmin',
  '/v1/webmaster',
  '/v1/administrator',
  '/v1/rootadmin',
  '/v1/globaladmin',

  // New File Traps
  '/v1/backup.tar',
  '/v1/backup.7z',
  '/v1/backup.rar',
  '/v1/dump.rdb',
  '/v1/dump.aof',
  '/v1/backup.mongodump',
  '/v1/backup.pgdump',
  '/v1/backup.sqlite',
  '/v1/backup.db',
  '/v1/snapshot.zip',

  // New Version Control Traps
  '/v1/.svn',
  '/v1/.hg',
  '/v1/.bzr',
  '/v1/.cvs',
  '/v1/.gitignore',
  '/v1/.gitmodules',
  '/v1/.git/HEAD',
  '/v1/.git/logs/HEAD',
  '/v1/.git/config',
  '/v1/.git/description',

  // New Debug Traps
  '/v1/_debug',
  '/v1/_debugbar',
  '/v1/_ignition',
  '/v1/_profiler',
  '/v1/_trace',
  '/v1/_dump',
  '/v1/_var_dump',
  '/v1/_phpinfo',
  '/v1/_xdebug',
  '/v1/_whoops',

  // New Health Check Traps
  '/v1/_health',
  '/v1/_status',
  '/v1/_ready',
  '/v1/_alive',
  '/v1/_heartbeat',
  '/v1/_ping',
  '/v1/_uptime',
  '/v1/_metrics',
  '/v1/_prometheus',
  '/v1/_stats',

  // New Documentation Traps
  '/v1/_docs',
  '/v1/_swagger',
  '/v1/_openapi',
  '/v1/_api-docs',
  '/v1/_raml',
  '/v1/_redoc',
  '/v1/_postman',
  '/v1/_insomnia',
  '/v1/_graphql-voyager',
  '/v1/_graphql-playground',
];

// Rate limiters
const rateLimiterByFingerprint = new RateLimiterMemory({
  points: 20,
  duration: 10,
});

const rateLimiterByIP = new RateLimiterMemory({
  points: 30,
  duration: 10,
});

// Generate fingerprint
function generateFingerprint(req: Request): string {
  const ua = req.headers['user-agent'] || '';
  const lang = req.headers['accept-language'] || '';
  const dnt = req.headers['dnt'] || '';
  const conn = req.headers['connection'] || '';
  const raw = [ua, lang, dnt, conn].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Headless browser detection
function isHeadlessUA(ua: string): boolean {
  const indicators = [
    'HeadlessChrome',
    'Puppeteer',
    'Selenium',
    'PhantomJS',
    'WebDriver',
  ];
  return indicators.some((ind) => ua.includes(ind));
}

// Fun hacker insults
const hackerMessages = [
  'Access denied. Go cry to your botnet mommy 😭',
  'Detected your bot. GTFO script kiddie 💩',
  "You think you're slick? Not today, bro 💻🛡️",
  'Hey bot, rate limit says hello 👋',
  'Another day, another clown with a proxy 😴',
  "You're not Neo. This ain’t the Matrix 🤡",
];

// Main middleware
export async function advancedSecurityMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const ua = req.headers['user-agent'] || '';
    const ip = req.ip ?? '';
    const fingerprint = generateFingerprint(req);

    // Honeypot route check (via array)
    if (honeypotPaths.includes(req.path)) {
      res.status(403).json({
        message: 'Access denied. You just stepped into a trap, clown 🤡',
      });
      return;
    }

    // Headless browser detection
    if (isHeadlessUA(ua)) {
      res.status(429).json({
        message:
          'Access denied. Nice try, you headless script kiddie loser 👊😎',
      });
      return;
    }

    await rateLimiterByFingerprint.consume(fingerprint);
    await rateLimiterByIP.consume(ip);

    // Apply security headers
    helmet()(req, res, () => {});

    next();
  } catch {
    const randomInsult =
      hackerMessages[Math.floor(Math.random() * hackerMessages.length)];

    res.status(429).json({ message: randomInsult });
  }
}
