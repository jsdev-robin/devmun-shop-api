import { NextFunction, Request, Response } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import jwt from 'jsonwebtoken';
import { Model } from 'mongoose';
import config from '../../../configs/config';
import { nodeClient } from '../../../configs/redis';
import { catchAsync } from '../../../libs/catchAsync';
import ApiError from '../../../middlewares/errors/ApiError';
import {
  IAddress,
  IFeedback,
  IPasswordUpdate,
  IProfile,
  ISettings,
  ISignin,
  ISignup,
  IUpdateEmail,
  IUser,
  IVerifyEmail,
  Role,
} from '../../../types/authTypes';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import Status from '../../../utils/status';
import { SendMail } from '../../email/SendMail';
import { Crypto, Decipheriv } from '../../security/CryptoServices';
import { IAuthCookies } from '../types/auth-types';
import { AuthKit } from './AuthKit';
import { TokenSignature } from './TokenService';

export interface AuthServiceOptions<T> {
  model: Model<T>;
  cookies: IAuthCookies;
  role: Role;
}

export class AuthService<T extends IUser> extends AuthKit {
  private readonly model: Model<T>;
  private readonly role: Role;

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
      // Extract user input from request body
      const { firstName, lastName, email, password } = req.body;

      // Normalize the email for comparison
      const normEmail = this.normalizeMail(email);

      // Check if user already exists with same email or normalized Gmail
      const userExists = await this.model
        .findOne({
          $or: [{ email }, { normalizeMail: normEmail }],
        })
        .exec();

      // If user exists, return error
      if (userExists) {
        return next(
          new ApiError(
            'This email is already registered. Use a different email address.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // Prepare user data for OTP creation
      const data = {
        firstName,
        lastName,
        email,
        normalizeMail: normEmail,
        password,
      };

      // Generate OTP and token for verification
      const { token, solidOTP } = await this.creatOtp(data, req);

      // Prepare email data for sending OTP
      const mailData = {
        user: {
          name: firstName,
          email,
        },
        otp: solidOTP,
      };

      // Send verification email and respond accordingly
      await new SendMail(mailData)
        .verifyEmail()
        .then(() => {
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
      req: Request<unknown, unknown, IVerifyEmail>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      const { otp, token } = req.body;

      // Decrypt token to retrieve encrypted user data
      const { encrypted } = jwt.verify(token, config.ACTIVATION_SECRET) as {
        encrypted: Decipheriv;
      };

      // Decrypt the encrypted user data
      const { firstName, lastName, email, normalizeMail, password, solidOTP } =
        await Crypto.decipheriv<{
          firstName: string;
          lastName: string;
          email: string;
          normalizeMail: string;
          password: string;
          solidOTP: string;
        }>(encrypted, config.CRYPTO_SECRET);

      // Validate OTP
      if (Number(solidOTP) !== Number(otp)) {
        return next(
          new ApiError(
            'The OTP you entered does not match. Please double-check the code and try again.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // Create new verified user
      await this.model.create({
        firstName,
        lastName,
        email,
        normalizeMail,
        password,
        role: this.role,
        status: {
          verified: true,
        },
      });

      // Send success response
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
        .select('+password +status')
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

      // If user account is explicitly marked as deactivated, block login
      if (user?.status?.isDeactivated) {
        return next(
          new ApiError(
            'Account deactivated. Contact support.',
            HttpStatusCode.FORBIDDEN
          )
        );
      }

      // Remove sensitive fields from user object before attaching to request
      user.password = undefined;
      user.status = undefined;

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
        const [accessToken, refreshToken] = this.rotateToken(
          req,
          user.id,
          user.role,
          remember
        );

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
        if (!decoded || this.checkClientSignature(decoded, req)) {
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

  public restrictTo = (...roles: Role[]) => {
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
        const [accessToken, refreshToken] = this.rotateToken(
          req,
          decoded.id,
          decoded.role,
          decoded.remember
        );

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

  public getSessions = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Get authenticated user from request
      const user = req.self;

      // Return error if no user found
      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // Query user's session tokens with:
      const result = await this.model
        .findById(user._id)
        .select({
          sessionToken: {
            $map: {
              input: {
                $sortArray: {
                  input: '$sessionToken',
                  sortBy: { createAt: -1 },
                },
              },
              as: 'token',
              in: {
                token: '$$token.token',
                device: '$$token.device',
                ip: '$$token.ip',
                browser: '$$token.browser',
                location: '$$token.location',
                city: '$$token.city',
                region: '$$token.region',
                country: '$$token.country',
                loc: '$$token.loc',
                org: '$$token.org',
                postal: '$$token.postal',
                timezone: '$$token.timezone',
                status: '$$token.status',
                createAt: '$$token.createAt',
              },
            },
          },
          _id: 0,
        })
        .lean()
        .exec();

      // Return sorted session history
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Sign-in history fetched successfully.',
        sessions: result?.sessionToken || [],
        total: result?.sessionToken?.length || 0,
      });
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

  public checkAccountDeactivated = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const user = req.self;

      // If user account is explicitly marked as deactivated, block login
      if (user.status.isDeactivated) {
        return next(
          new ApiError(
            'Account deactivated. Contact support.',
            HttpStatusCode.FORBIDDEN
          )
        );
      }

      next();
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

  public updateProfile = catchAsync(
    async (
      req: Request<unknown, unknown, IProfile>,
      res: Response
    ): Promise<void> => {
      // Update user document with new data
      const user = await this.model
        .findByIdAndUpdate(req.self?._id, req.body, {
          new: true,
        })
        .lean();

      // Update Redis cache with new user data
      (async () => {
        try {
          const multi = nodeClient.multi();
          multi.json.SET(`${user?._id}`, '$', Object(user));
          await multi.EXEC();
        } catch (err) {
          console.error('Redis cache update failed:', err);
        }
      })();

      // Send success response
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Profile updated successfully.',
      });
    }
  );

  public getProfileFields = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const query = this.sanitizeFields(req.query, 'fields');

      // Explicitly include settings fields in projection
      const user = await this.model
        .findById(req.self?._id)
        .select(String(query).split(',').join(' '))
        .lean()
        .exec();

      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      // Return only what was requested (or add warning if you need to keep current behavior)
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'User fields retrieved successfully',
        data: {
          user,
        },
      });
    }
  );

  public updatePassword = catchAsync(
    async (
      req: Request<ParamsDictionary, unknown, IPasswordUpdate>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      const { currentPassword, newPassword } = req.body;

      // Retrieve the authenticated user with password field
      const user = await this.model.findById(req.self?._id).select('+password');

      // Validate the current password and ensure user exists
      if (!(await user?.isPasswordValid(currentPassword)) || !user) {
        return next(
          new ApiError(
            'The current password you entered is incorrect. Please double-check and try again.',
            HttpStatusCode.UNAUTHORIZED
          )
        );
      }

      // Check if new password is same as current password
      if (await user.isPasswordValid(newPassword)) {
        return next(
          new ApiError(
            'New password must be different from the current password.',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      await this.clearOtherSessions({
        req,
        model: this.model,
        id: user?.id,
      });

      // Update user's password
      user.password = newPassword;
      await user.save();

      // Send success response
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message:
          'Your password has been updated successfully. Please use your new password the next time you log in.',
      });
    }
  );

  public requestEmailUpdate = (url: string) =>
    catchAsync(
      async (
        req: Request<unknown, unknown, IUpdateEmail>,
        res: Response,
        next: NextFunction
      ): Promise<void> => {
        const { newEmail, password } = req.body;

        // Check if new email is already in use
        const normalizeGmail = this.normalizeMail(newEmail);
        const emailExists = await this.model
          .findOne({
            $or: [{ newEmail }, { normalizeGmail }],
          })
          .exec();
        if (emailExists) {
          return next(
            new ApiError(
              'This email is already in use by another account.',
              HttpStatusCode.CONFLICT
            )
          );
        }

        // Fetch user including password for validation
        const user = await this.model
          .findById(req.self?._id)
          .select('+password');

        // Check if user exists and password is valid
        if (!user || !(await user.isPasswordValid(password))) {
          return next(
            new ApiError(
              'The current password you entered is incorrect. Please double-check and try again.',
              HttpStatusCode.UNAUTHORIZED
            )
          );
        }

        // Metadata for email update context (IP, device info, etc.)
        const clientMeta = {
          ip: req.ip,
          location: req.ipinfo?.location,
          device: req.useragent?.os,
          oldEmail: user.email,
          newEmail: newEmail,
          normalizeGmail: normalizeGmail,
        };

        // Encrypt clientMeta
        const encrypted = await Crypto.cipheriv(
          { ...clientMeta, purpose: 'email-change' },
          config.CRYPTO_SECRET
        );

        // Sign the encrypted payload in JWT
        const token = jwt.sign({ encrypted }, config.CRYPTO_SECRET, {
          expiresIn: '1d',
          algorithm: 'HS256',
        });

        // Prepare email payload with relevant info
        const emailPayload = {
          user: {
            name: user.firstName,
            email: newEmail,
          },
          url: `${url}?token=${token}`,
          ...clientMeta,
        };

        // Send verification email with confirmation link
        await new SendMail(emailPayload)
          .emailChangeRequest()
          .then(() => {
            res.status(HttpStatusCode.OK).json({
              status: Status.SUCCESS,
              message:
                'A verification link has been sent to your current email address. Please check your inbox and click the link to confirm the email update.',
            });
          })
          .catch(() => {
            next(
              new ApiError(
                'An error occurred while sending the verification email. Please try again later.',
                HttpStatusCode.INTERNAL_SERVER_ERROR
              )
            );
          });
      }
    );

  public updateEmail = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // Verify JWT and extract encrypted data
      const { encrypted } = jwt.verify(
        String(req.query.token),
        config.CRYPTO_SECRET
      ) as {
        encrypted: Decipheriv;
      };

      // Decrypt the encrypted user data from token
      const {
        // ip: string;
        // location?: string;
        // device?: string;
        oldEmail,
        newEmail,
        normalizeMail,
      } = await Crypto.decipheriv<{
        oldEmail: string;
        newEmail: string;
        normalizeMail: string;
      }>(encrypted, config.CRYPTO_SECRET);

      // Find user by old email
      const user = await this.model.findOne({ email: oldEmail });
      if (!user) {
        return next(
          new ApiError(
            'User not found or already updated. Please request a new email change.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      await this.clearOtherSessions({
        req,
        model: this.model,
        id: user?.id,
      });

      user.email = newEmail;
      user.normalizeMail = normalizeMail;
      await user.save();

      // Respond with success message
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Your email has been successfully updated.',
      });
    }
  );

  public updateSettings = catchAsync(
    async (
      req: Request<unknown, unknown, ISettings>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Find user by ID including the 'settings' field
      const user = await this.model.findById(req.self?._id).select('+settings');

      // Handle case if user not found
      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      // Merge existing settings with incoming updates
      user.settings = {
        ...user.settings,
        ...req.body,
      };

      // Save updated user document
      await user.save();

      // Respond with success and updated user data
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Your settings have been successfully updated.',
      });
    }
  );

  public updateAddresses = catchAsync(
    async (
      req: Request<unknown, unknown, IAddress>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      // Get user with addresses
      const user = await this.model
        .findById(req.self?._id)
        .select('+addresses');

      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      // Add new address to array
      user.addresses.push(req.body);
      await user.save();

      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message: 'New address added successfully',
      });
    }
  );

  public deleteAddresses = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const addressId = req.query.addressId as string;

      // Find and remove address in single operation
      const user = await this.model.findOneAndUpdate(
        { _id: req.self?._id, 'addresses._id': addressId },
        { $pull: { addresses: { _id: addressId } } },
        { new: true, select: '+addresses' }
      );

      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      res.status(HttpStatusCode.NO_CONTENT).json({
        status: Status.SUCCESS,
        message: 'Address removed successfully',
      });
    }
  );

  public updateFeedback = catchAsync(
    async (
      req: Request<unknown, unknown, IFeedback>,
      res: Response,
      next: NextFunction
    ): Promise<void> => {
      const user = await this.model
        .findById(req.self?._id)
        .select('+feedbacks +status');

      if (!user) {
        return next(
          new ApiError(
            'No user found. Please log in again to access your account.',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      // Update user status and add feedback
      if (user.status && user.feedbacks) {
        user.status = {
          ...user.status,
          isDeactivated: true,
        };
        user.feedbacks.push({
          ...req.body,
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        // Save changes to user
        await user.save();
      }

      // Clear sessions from database
      const sessionUserInDB = await this.model
        .updateOne({ _id: user._id }, { $unset: { sessionToken: '' } })
        .exec();

      if (sessionUserInDB.modifiedCount === 0) {
        return next(
          new ApiError(
            `Failed to clear sessions for user: ${user._id}`,
            HttpStatusCode.INTERNAL_SERVER_ERROR
          )
        );
      }

      // Clear sessions from Redis
      const p = nodeClient.multi();
      p.DEL(`${user._id}:session`);
      p.DEL(`${user._id}`);
      const [del] = await p.exec();

      if (!del) {
        return next(
          new ApiError(
            'Failed to clear session data',
            HttpStatusCode.INTERNAL_SERVER_ERROR
          )
        );
      }

      // Clear cookies
      this.clearAllCookies(res);

      // Send final response
      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message:
          'We appreciate your feedback. Your account has been deactivated. Remember, you can reactivate your account within 30 days by simply logging back in. We hope to see you again!',
      });
    }
  );

  public getUsers = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // 1. Pagination
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const skip = (page - 1) * limit;

      // 2. Field selection
      const fields =
        (req.query.fields as string)?.split(',')?.join(' ') ||
        '-password -__v -sessionToken';

      // 3. Sorting
      const sortBy =
        (req.query.sort as string)?.split(',')?.join(' ') || '-createdAt';

      // 4. Filtering
      const queryObj = { ...req.query };
      const excludedFields = ['page', 'limit', 'sort', 'fields'];
      excludedFields.forEach((el) => delete queryObj[el]);

      // Advanced filtering
      let queryStr = JSON.stringify(queryObj);
      queryStr = queryStr.replace(
        /\b(gte|gt|lte|lt)\b/g,
        (match) => `$${match}`
      );

      // 5. Build query
      const baseQuery = this.model.find({
        ...JSON.parse(queryStr),
        _id: { $ne: req.self?._id },
      });

      // 6. Execute queries
      const [users, total] = await Promise.all([
        baseQuery
          .clone()
          .select(fields)
          .sort(sortBy)
          .skip(skip)
          .limit(limit)
          .lean()
          .exec(),
        this.model.countDocuments(baseQuery.getFilter()),
      ]);

      // 7. Handle no users found
      if (users.length === 0) {
        return next(
          new ApiError(
            'No users found matching the specified criteria',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      // 8. Successful response
      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Users retrieved successfully',
        data: {
          users,
          pagination: {
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            itemsPerPage: limit,
            hasNextPage: page < Math.ceil(total / limit),
            hasPrevPage: page > 1,
            nextPage: page < Math.ceil(total / limit) ? page + 1 : null,
            prevPage: page > 1 ? page - 1 : null,
          },
        },
      });
    }
  );
}

export default AuthService;
