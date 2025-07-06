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
import config from './configs/config';
import ApiError from './middlewares/errors/ApiError';
import globalErrorHandler from './middlewares/errors/globalError';
import {
  initializePassport,
  passport,
} from './middlewares/passports/passports';
import HttpStatusCode from './utils/HttpStatusCode';
import Status from './utils/status';

import shopAuthRouter from './apps/shop/routes/shopAuthRoutes';
import shopProductRouter from './apps/shop/routes/shopProductRoutes';

const app: Application = express();

// Development logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

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
// Set security-related HTTP headers
app.use(helmet());

// Proxy middleware
app.set('trust proxy', 1);

// Serving static files
app.use(express.static(path.join(__dirname, './src/views')));
app.use(express.static(path.join(__dirname, 'public')));

// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

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
      'http://localhost:3000',
      'http://localhost:3001',
    ],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);

// Serialize user into the session
initializePassport();
app.use(passport.initialize());
app.use(passport.session());

// Serialize user into the session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from the session
passport.deserializeUser((user: Express.User, done) => {
  done(null, user);
});

app.get('/', (_, res) => {
  res.status(HttpStatusCode.OK).json({
    success: Status.SUCCESS,
    message: 'API is working well 🚀',
    environment: config.ISPRODUCTION ? 'production' : 'development',
  });
});

// app.get('/', (req, res) => {
//   res.send(
//     `<a href="/api/v1/dashboard/user/auth/google">Login with Google</a>`
//   );
// });

// Global route

// Shop route
app.use('/v1/shop/user/auth', shopAuthRouter);
app.use('/v1/shop', shopProductRouter);

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
