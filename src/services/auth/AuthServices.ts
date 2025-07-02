import { NextFunction, Request, Response } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import jwt from 'jsonwebtoken';
import { Model } from 'mongoose';
import config from '../../configs/config';
import { catchAsync } from '../../libs/catchAsync';
import ApiError from '../../middlewares/errors/ApiError';
import { IUser, UserRole } from '../../types/user';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';
import { SendMailServices } from '../email/SendMailServices';
import { Crypto, Decipheriv } from '../security/CryptoServices';
import { AuthKit } from './particles/AuthKit';
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

  public signin = catchAsync(
    async (
      req: Request<unknown, unknown, ISignin>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Extract login credentials and remember flag from request body
      const { email, password, remember } = req.body;

      // Find user by email and include password for validation
      const user = await this.model
        .findOne({ email })
        .select('+password')
        .exec();

      // Check if user exists and password is correct
      if (!user || !(await user.isPasswordValid(password))) {
        return next(
          new ApiError(
            'Incorrect email or password. Please check your credentials and try again.',
            HttpStatusCode.UNAUTHORIZED
          )
        );
      }

      // Remove sensitive fields from user object before attaching to request
      user.password = undefined;

      // Attach user info and remember flag to request for next middleware
      req.self = user;
      req.remember = remember;

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
}

export default AuthServices;
