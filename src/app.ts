import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { Application, NextFunction, Request, Response } from 'express';
import session from 'express-session';
import useragent from 'express-useragent';
import helmet from 'helmet';
import ipinfo, { defaultIPSelector } from 'ipinfo-express';
import morgan from 'morgan';
import path from 'path';
import swaggerUi from 'swagger-ui-express';
import config from './configs/config';
import * as swaggerDocument from './docs/swagger-output.json';
import ApiError from './middlewares/errors/ApiError';
import globalErrorHandler from './middlewares/errors/globalError';
import { rateLimiter } from './middlewares/rateLimiter';
import HttpStatusCode from './utils/HttpStatusCode';
import Status from './utils/status';

import { advancedSecurityMiddleware } from './middlewares/advancedSecurityMiddleware';
import productRouter from './routes/productRoute';
import sellerAuthRouter from './routes/sellerAuthRoute';

const app: Application = express();

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

app.use(advancedSecurityMiddleware);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Session middleware
app.use(
  session({
    secret: 'dddd',
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 24 * 60 * 1000,
    },
  })
);

// Apply the rate limiting middleware to all requests.
app.use(rateLimiter());

// Set security-related HTTP headers
app.use(helmet());

// Proxy middleware
app.set('trust proxy', 1);

// Serving static files
app.use(express.static(path.join(__dirname, './src/views')));
app.use(express.static(path.join(__dirname, 'public')));

// Parse request bodies
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Parse cookies
app.use(cookieParser(config.COOKIE_SECRET));

// Get user device info
app.use(useragent.express());

// Get req  location
app.use(
  ipinfo({
    token: config.IPINFO_KEY,
    cache: null,
    timeout: 5000,
    ipSelector: defaultIPSelector,
  })
);

// Configure Cross-Origin Resource Sharing (CORS)
app.use(
  cors({
    origin: [
      'https://shop.devmun.xyz',
      'https://shop-hub.devmun.xyz',
      'http://localhost:3000',
      'http://localhost:3001',
    ],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

app.get('/', (_, res) => {
  res.status(HttpStatusCode.OK).json({
    success: Status.SUCCESS,
    message: 'API is working well 🚀',
    environment: config.ISPRODUCTION ? 'production' : 'development',
  });
});

// Shop route
app.use('/v1/seller/auth', sellerAuthRouter);
app.use('/v1/product', productRouter);

// Handle 404 errors
app.all(/(.*)/, (req: Request, res: Response, next: NextFunction) => {
  return next(
    new ApiError(
      `Can't find ${req.originalUrl} on this server!`,
      HttpStatusCode.NOT_FOUND
    )
  );
});

// Global error handling middleware
app.use(globalErrorHandler);

export default app;
