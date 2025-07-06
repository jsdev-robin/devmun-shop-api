import { NextFunction, Request, Response } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import jwt from 'jsonwebtoken';
import { Model } from 'mongoose';
import config from '../../configs/config';
import { nodeClient } from '../../configs/redis';
import { catchAsync } from '../../libs/catchAsync';
import ApiError from '../../middlewares/errors/ApiError';
import { IUser, UserRole } from '../../types/user';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';
import { SendMailServices } from '../email/SendMailServices';
import { Crypto, Decipheriv } from '../security/CryptoServices';
import { AuthKit } from './particles/AuthKit';
import { TokenSignature } from './particles/TokenService';
import {
  AuthServiceOptions,
  ISignin,
  ISignup,
  IVerifyEmail,
} from './types/authTypes';

export class AuthServices<T extends IUser> extends AuthKit {
  private readonly model: Model<T>;
  private readonly role: UserRole;

  constructor(options: AuthServiceOptions<T>) {
    super(options);
    this.model = options.model;
    this.role = options.role;
  }

  public signup = catchAsync(
    async (
      req: Request<ParamsDictionary, unknown, ISignup>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Destructure user input from request body
      const { firstName, lastName, email, password } = req.body;

      // Normalize the email for consistency (e.g., lowercase, trimmed)
      const normEmail = this.normalizeMail(email);

      // Check if a user already exists with the same email or normalized email
      const userExists = await this.model
        .findOne({
          $or: [{ email }, { normalizeMail: normEmail }],
        })
        .exec();

      // If user exists, return a 400 error with message
      if (userExists) {
        return next(
          new ApiError(
            'This email is already registered. Use a different email address.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // Prepare user data for OTP creation and storage
      const data = {
        firstName,
        lastName,
        email,
        normalizeMail: normEmail,
        password,
      };

      // Generate OTP and token for email verification
      const { token, solidOTP } = await this.creatOtp(data, req);

      // Prepare data for the verification email
      const mailData = {
        user: {
          name: firstName,
          email,
        },
        otp: solidOTP,
      };

      // Send verification email and respond accordingly
      await new SendMailServices(mailData)
        .verifyEmail()
        .then(() => {
          // On success, send OK response with verification token
          res.status(HttpStatusCode.OK).json({
            status: Status.SUCCESS,
            message:
              'Verification code sent successfully to your email address.',
            data: {
              token,
            },
          });
        })
        .catch(() => {
          // On failure, pass error to the next middleware
          next(
            new ApiError(
              'An error occurred while sending the verification email. Please try again later.',
              HttpStatusCode.INTERNAL_SERVER_ERROR
            )
          );
        });
    }
  );

  public verifyEmail = catchAsync(
    async (
      req: Request<ParamsDictionary, unknown, IVerifyEmail>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Destructure OTP and token from request body
      const { otp, token } = req.body;

      // Verify JWT token and extract the encrypted payload
      const { encrypted } = jwt.verify(token, config.ACTIVATION_SECRET) as {
        encrypted: Decipheriv;
      };

      // Decrypt the encrypted payload to retrieve user information
      const { firstName, lastName, email, normalizeMail, password, solidOTP } =
        await Crypto.decipheriv<{
          firstName: string;
          lastName: string;
          email: string;
          normalizeMail: string;
          password: string;
          solidOTP: string;
        }>(encrypted, config.CRYPTO_SECRET);

      // Compare provided OTP with the decrypted solidOTP
      if (Number(solidOTP) !== Number(otp)) {
        return next(
          new ApiError(
            'The OTP you entered does not match. Please double-check the code and try again.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // Construct the user payload including email verification log
      const payload = {
        name: {
          first: firstName,
          last: lastName,
        },
        email: email,
        normalizeMail: normalizeMail,
        password: password,
        emailChangeLog: this.genEmailLog({ email, req }),
      };

      // Create a new user record if OTP matches
      await this.model.create(payload);

      // Respond with a success message
      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message: 'Your account has been successfully verified.',
      });
    }
  );

  public accountLock = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Check for the presence of a signed cookie indicating the account is locked
      const isLocked = req.signedCookies['x389kld'];

      // If the lock cookie is present, block further requests with a LOCKED error
      if (isLocked) {
        return next(
          new ApiError(
            'Account locked due to multiple failed login attempts. Please try again after 15 minutes.',
            HttpStatusCode.LOCKED
          )
        );
      }

      // Proceed to the next middleware if no lock cookie is found
      next();
    }
  );

  public signin = catchAsync(
    async (
      req: Request<unknown, unknown, ISignin>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Extract login fields from request body
      const { email, password, remember } = req.body;

      // Look up user by email, including password and loginAttempts fields
      const user = await this.model
        .findOne({ email })
        .select('+password +loginAttempts')
        .exec();

      // Apply account lock policy (may block user if lock threshold met)
      await this.enforceLockPolicy(res, next, user);

      // If response was already sent by enforceLockPolicy, exit early
      if (res.headersSent) return;

      // Validate user existence and password
      if (!user || !(await user.isPasswordValid(password))) {
        // Increment login attempts only if user exists
        await user?.incrementLoginAttempts();

        // Send unauthorized error response for invalid credentials
        return next(
          new ApiError(
            'Incorrect email or password. Please check your credentials and try again.',
            HttpStatusCode.UNAUTHORIZED
          )
        );
      }

      // Reset login attempts after successful authentication
      if (user.loginAttempts?.attempts) {
        res.clearCookie('x389kld');
        await user?.resetLoginAttempts();
      }

      // Remove sensitive password field before continuing
      user.password = undefined;

      // Attach authenticated user and session preference to request object
      req.self = user;
      req.remember = remember;

      // Proceed to the next middleware (e.g., session/token generation)
      next();
    }
  );

  public createSession = (url?: string) =>
    catchAsync(
      async (
        req: Request,
        res: Response,
        next: NextFunction
      ): Promise<void> => {
        const user = req.self;
        const remember = req.remember;
        const redirect = req.redirect;

        // Generate access and refresh tokens
        const [accessToken, refreshToken] = this.rotateToken(req, {
          ...user,
          remember,
        });

        // Set access and refresh tokens as cookies
        res.cookie(...this.createAccessCookie(accessToken, remember));
        res.cookie(...this.createRefreshCookie(refreshToken, remember));

        try {
          // Store session in Redis and database concurrently
          await this.storeSession({
            Model: this.model,
            req,
            user,
            accessToken,
          });

          // Handle response: either redirect or JSON response
          if (redirect) {
            res.redirect(`${url}?role=${user?.role}`);
          } else {
            res.status(HttpStatusCode.OK).json({
              status: Status.SUCCESS,
              message: `Welcome back ${user?.firstName}.`,
              role: user?.role ?? 'user',
            });
          }
        } catch (error) {
          this.clearAllCookies(res);
          next(error);
        }
      }
    );

  public validateToken = catchAsync(
    async (
      req: Request<ParamsDictionary, unknown, unknown> & {
        userId?: string | undefined;
        accessToken?: string | undefined;
      },
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      const accessCookie = req.signedCookies[this.getAccessCookieConfig().name];

      // If the access token is missing, throw an unauthorized error
      if (!accessCookie) {
        return this.sessionUnauthorized(res, next);
      }

      try {
        // Verify the access token and decode the payload
        const decoded = jwt.verify(accessCookie, config.ACCESS_TOKEN) as {
          id: string;
        } & TokenSignature;

        // Attach user ID and access token to the request object
        req.userId = decoded?.id;
        req.accessToken = accessCookie;

        // Validate the decrypted IP against the request IP
        if (!decoded || this.checkTokenSignature(decoded, req)) {
          return this.sessionUnauthorized(res, next);
        }

        next();
      } catch (error) {
        this.clearAllCookies(res);
        next(error);
      }
    }
  );

  public requireAuth = catchAsync(
    async (
      req: Request<unknown, unknown, unknown> & {
        userId?: string | undefined;
        accessToken?: string | undefined;
      },
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Get credentials from request
      const { userId, accessToken } = req;

      // Query session and user data from Redis
      const p = nodeClient.multi();

      p.SISMEMBER(`${userId}:session`, Crypto.hmac(String(accessToken)));
      p.json.GET(`${userId}`);

      const [sessionToken, cachedUser] = await p.exec();

      // Invalidate if session/user not found
      if (!sessionToken || !cachedUser) {
        return this.sessionUnauthorized(res, next);
      }

      // Resolve user from Redis or fallback to database
      const user = cachedUser || (await this.model.findById(userId).exec());

      if (!user) {
        return next(
          new ApiError(
            "We couldn't find your account. Please contact support if you believe this is an error.",
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      req.self = user;
      next();
    }
  );

  public restrictTo = (...roles: UserRole[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
      const user = req.self;
      if (!user?.role || !roles.includes(user.role)) {
        const error = new ApiError(
          'You do not have permission to perform this action',
          HttpStatusCode.FORBIDDEN
        );
        next(error);
        return;
      }

      next();
    };
  };

  public refreshToken = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Get refresh token from cookies
      const refreshCookie = req.cookies[this.getRefreshCookieConfig().name];

      // Exit early if no refresh token is found
      if (!refreshCookie) {
        return this.sessionUnauthorized(res, next);
      }

      try {
        // Verify and decode the refresh token payload
        const decoded = jwt.verify(
          refreshCookie,
          config.REFRESH_TOKEN
        ) as TokenSignature;

        // Rotate access and refresh tokens
        const [accessToken, refreshToken] = this.rotateToken(req, {
          id: decoded.id,
          role: decoded.role,
          remember: decoded.remember,
        });

        // Hash new access token for Redis and DB session comparison
        const oldToken = decoded.token;
        const newToken = Crypto.hmac(String(accessToken));

        // Rotate session in Redis: remove old and add new token
        await this.rotateSession({
          model: this.model,
          id: decoded.id,
          oldToken,
          newToken,
        });

        // Set newly issued tokens in cookies
        res.cookie(...this.createAccessCookie(accessToken, decoded.remember));
        res.cookie(...this.createRefreshCookie(refreshToken, decoded.remember));

        // Respond with success message
        res.status(200).json({
          status: Status.SUCCESS,
          message: 'Token refreshed successfully.',
        });
      } catch (error) {
        this.clearAllCookies(res);
        next(error);
      }
    }
  );

  public signout = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const accessToken = req.signedCookies[this.getAccessCookieConfig().name];
      const user = req.self;

      try {
        await this.removeASession({
          model: this.model,
          res,
          id: user.id,
          token: Crypto.hmac(accessToken),
        });

        res.status(HttpStatusCode.OK).json({
          status: Status.SUCCESS,
          message: 'You have been successfully signed out.',
        });
      } catch (error) {
        this.clearAllCookies(res);
        next(error);
      }
    }
  );

  public signoutSession = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Extract the session token from request parameters
      const { token } = req.params;
      const user = req.self;

      // Validate that token is provided
      if (!token) {
        return next(
          new ApiError(
            'Token is required.',
            HttpStatusCode.INTERNAL_SERVER_ERROR
          )
        );
      }

      await this.removeASession({
        model: this.model,
        res,
        id: user.id,
        token: token,
      });

      // Send a success response indicating logout completion
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'You have been successfully logged out.',
      });
    }
  );

  public signoutAllSession = catchAsync(
    async (req: Request, res: Response): Promise<void> => {
      const user = req.self;

      await this.removeAllSessions({
        model: this.model,
        id: user.id,
      });

      this.clearAllCookies(res);
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'You have been successfully logged out.',
      });
    }
  );

  // ================== Manage user information ==================
  public getProfile = catchAsync(
    async (req: Request, res: Response): Promise<void> => {
      // User is already attached to request via auth middleware
      const user = req.self;

      // Consider returning only necessary profile data
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Profile retrieved successfully',
        data: {
          user,
        },
      });
    }
  );
}

export default AuthServices;
