import { randomInt } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Document, Model } from 'mongoose';
import config from '../../../configs/config';
import { nodeClient } from '../../../configs/redis';
import ApiError from '../../../middlewares/errors/ApiError';
import { IUser } from '../../../types/user';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { cookieOptions, enableSignature, refreshTTL } from './CookieService';
import { TokenService } from './TokenService';

export class AuthKit extends TokenService {
  private getDeviceInfo = (req: Request) => {
    const ua = req.useragent;
    const deviceType = ua?.isSmartTV
      ? 'smart-tv'
      : ua?.isBot
      ? 'bot'
      : ua?.isMobileNative
      ? 'mobile-native'
      : ua?.isMobile
      ? 'mobile'
      : ua?.isTablet
      ? 'tablet'
      : ua?.isAndroidTablet
      ? 'android-tablet'
      : ua?.isiPad
      ? 'ipad'
      : ua?.isiPhone
      ? 'iphone'
      : ua?.isiPod
      ? 'ipod'
      : ua?.isKindleFire
      ? 'kindle-fire'
      : ua?.isDesktop
      ? 'desktop'
      : ua?.isWindows
      ? 'windows'
      : ua?.isMac
      ? 'mac'
      : ua?.isLinux
      ? 'linux'
      : ua?.isChromeOS
      ? 'chromeos'
      : ua?.isRaspberry
      ? 'raspberry-pi'
      : 'unknown';

    return {
      deviceType,
      os: ua?.os ?? 'unknown',
      browser: ua?.browser ?? 'unknown',
      userAgent: req.headers['user-agent'] ?? 'unknown',
    };
  };

  private getLocationInfo = (req: Request) => ({
    city: req.ipinfo?.city || 'unknown',
    country: req.ipinfo?.country || 'unknown',
    lat: Number(req.ipinfo?.loc?.split(',')[0]) || 0,
    lng: Number(req.ipinfo?.loc?.split(',')[1]) || 0,
  });

  protected creatOtp = async (
    data: object,
    req: Request
  ): Promise<{ token: string; solidOTP: number }> => {
    try {
      const otpMin = Math.pow(10, 6 - 1);
      const otpMax = Math.pow(10, 6) - 1;

      const solidOTP = randomInt(otpMin, otpMax);

      const encrypted = await Crypto.cipheriv(
        {
          ...data,
          solidOTP,
          ip: req.ip,
          browser: req.useragent?.browser,
          device: req.useragent?.os,
        },
        config.CRYPTO_SECRET
      );

      const token = jwt.sign({ encrypted }, config.ACTIVATION_SECRET, {
        expiresIn: '10m',
      });

      return { token, solidOTP };
    } catch {
      throw new ApiError(
        'Failed to create OTP. Please try again.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected normalizeMail = (email: string): string => {
    const [localPart, domain] = email.split('@');

    if (domain.toLowerCase() === 'gmail.com') {
      return localPart.replace(/\./g, '') + '@gmail.com';
    }

    return email.toLowerCase();
  };

  protected genEmailLog = ({
    email,
    req,
  }: {
    email: string;
    req: Request;
  }) => ({
    email,
    verified: true,
    verifiedAt: Date.now(),
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  });

  protected rotateSession = async <T extends IUser>({
    model,
    id,
    oldToken,
    newToken,
  }: {
    model: Model<T>;
    id: string;
    oldToken: string;
    newToken: string;
  }): Promise<void> => {
    try {
      await Promise.all([
        // Redis: replace old token with new one
        (async () => {
          const p = nodeClient.multi();
          p.SREM(`${id}:session`, String(oldToken));
          p.SADD(`${id}:session`, Crypto.hmac(String(newToken)));
          p.EXPIRE(`${id}:session`, refreshTTL * 24 * 60 * 60);
          await p.exec();
        })(),

        // DB: update token inside sessionToken array
        model
          .findByIdAndUpdate(
            id,
            {
              $set: {
                'sessionToken.$[elem].token': newToken,
              },
            },
            {
              arrayFilters: [{ 'elem.token': oldToken }],
              new: true,
            }
          )
          .exec(),
      ]);
    } catch {
      throw new ApiError(
        'Failed to rotate session. Please try again later.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected storeSession = async <T extends { _id: string | number }>({
    Model,
    req,
    user,
    accessToken,
  }: {
    Model: Model<T>;
    req: Request;
    user: T;
    accessToken: string;
  }): Promise<void> => {
    try {
      const hashedToken = Crypto.hmac(String(accessToken));

      await Promise.all([
        // Store session in Redis
        (async () => {
          const p = nodeClient.multi();

          p.SADD(`${user._id}:session`, hashedToken);
          p.json.SET(`${user._id}`, '$', Object(user));
          p.EXPIRE(`${user._id}:session`, refreshTTL * 24 * 60 * 60);
          p.EXPIRE(`${user._id}`, refreshTTL * 24 * 60 * 60);

          await p.exec();
        })(),

        // Store session info in MongoDB
        Model.findByIdAndUpdate(
          user._id,
          {
            $push: {
              sessions: {
                token: hashedToken,
                ip: req.ip,
                deviceInfo: this.getDeviceInfo(req),
                location: this.getLocationInfo(req),
                loggedInAt: new Date(),
                expiresAt: new Date(
                  Date.now() + refreshTTL * 24 * 60 * 60 * 1000
                ),
                revoked: false,
                revokedAt: null,
                lastActivityAt: new Date(),
                riskScore: 0,
                trustedDevice: false,
              },
            },
          },
          { new: true }
        ).exec(),
      ]);
    } catch {
      throw new ApiError(
        'Failed to store session.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected removeASession = async <T extends IUser>({
    model,
    res,
    id,
    token,
  }: {
    model: Model<T>;
    res: Response;
    id: string;
    token: string;
  }): Promise<void> => {
    try {
      await Promise.all([
        // Redis session removal
        (async () => {
          const p = nodeClient.multi();
          p.SREM(`${id}:session`, token);
          const [rem] = await p.exec();

          // Ensure the token was actually removed
          if (Number(rem) !== 1) {
            throw new Error('Token not found in session set.');
          }
        })(),

        // DB session token status update
        model
          .findByIdAndUpdate(
            id,
            {
              $set: {
                'sessionToken.$[elem].status': false,
              },
            },
            {
              arrayFilters: [{ 'elem.token': token }],
              new: true,
            }
          )
          .exec(),
      ]);

      // Clear cookies only after both Redis and DB succeed
      this.clearAllCookies(res);
    } catch {
      throw new ApiError(
        'Failed to remove session. Please try again later.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected removeAllSessions = async <T extends IUser>({
    model,
    id,
  }: {
    model: Model<T>;
    id: string;
  }): Promise<void> => {
    try {
      await Promise.all([
        // Clear all Redis session and user cache
        (async () => {
          const p = nodeClient.multi();
          p.DEL(`${id}:session`);
          p.DEL(`${id}`);
          await p.exec();
        })(),

        // Unset all sessionToken entries from database
        model.updateOne({ _id: id }, { $unset: { sessionToken: '' } }).exec(),
      ]);
    } catch {
      throw new ApiError(
        'Failed to remove all sessions.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected clearOtherSessions = async <T extends IUser>({
    req,
    model,
    id,
  }: {
    req: Request;
    model: Model<T>;
    id: string;
  }): Promise<void> => {
    try {
      const token = Crypto.hmac(
        req.signedCookies[this.getAccessCookieConfig().name]
      );
      await Promise.all([
        (async () => {
          const p = nodeClient.multi();
          p.DEL(`${id}:session`);
          p.SADD(`${id}:session`, token);
          await p.exec();
        })(),

        model
          .updateOne(
            { _id: id },
            {
              $pull: {
                sessionToken: {
                  token: { $ne: token },
                },
              },
            }
          )
          .exec(),
      ]);
    } catch {
      throw new ApiError(
        'Failed to clear other sessions.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected sessionUnauthorized = (res: Response, next: NextFunction) => {
    this.clearAllCookies(res);
    return next(
      new ApiError(
        'Your session has expired or is no longer available. Please log in again to continue.',
        HttpStatusCode.UNAUTHORIZED
      )
    );
  };

  protected sanitizeRequest = <T extends Record<string, unknown>>(
    obj: T,
    additionalFields: string[] = ['password', 'email', 'normalizeGmail']
  ): T => {
    additionalFields.forEach((field) => {
      if (field in obj) delete obj[field];
    });
    return obj;
  };

  protected sanitizeFields = <T extends Record<string, unknown>>(
    query: T,
    key: keyof T = 'fields' as keyof T,
    forbiddenFields: string[] = ['password', 'email', 'normalizeMail']
  ): string => {
    const raw = query[key];
    if (typeof raw !== 'string' || !raw.trim()) {
      return forbiddenFields.map((f) => `-${f}`).join(' ');
    }

    const allowedSet = new Set(
      raw
        .split(',')
        .map((f) => f.trim())
        .filter(Boolean)
        .map((f) => f.replace(/^[-+]/, ''))
    );

    forbiddenFields.forEach((field) => allowedSet.delete(field));
    return allowedSet.size > 0
      ? [...allowedSet].join(' ')
      : forbiddenFields.map((f) => `-${f}`).join(' ');
  };

  protected validateCurrentPassword = async <T extends IUser>(
    user: T | null | undefined,
    password: string,
    next: NextFunction
  ): Promise<boolean> => {
    if (!user || !(await user.isPasswordValid(password))) {
      next(
        new ApiError(
          'Current password is incorrect',
          HttpStatusCode.UNAUTHORIZED
        )
      );
      return false;
    }
    return true;
  };

  protected validateNewPassword = async <T extends IUser>(
    user: T | null | undefined,
    newPassword: string,
    next: NextFunction
  ): Promise<boolean> => {
    if (user && (await user.isPasswordValid(newPassword))) {
      next(
        new ApiError(
          'New password must be different',
          HttpStatusCode.BAD_REQUEST
        )
      );
      return false;
    }
    return true;
  };

  protected enforceLockPolicy = async (
    res: Response,
    next: NextFunction,
    user: (Document<unknown, unknown, IUser> & IUser) | null
  ): Promise<void> => {
    if (!user) return;

    if (user?.loginAttempts?.lock) {
      const lockTimePassed =
        user.loginAttempts.date &&
        Date.now() - user.loginAttempts.date.getTime() > 15 * 60 * 1000;

      if (!lockTimePassed) {
        res.cookie('x389kld', Crypto.randomHexString(), {
          ...cookieOptions,
          maxAge: 15 * 60 * 1000,
        });
        return next(
          new ApiError(
            'Account locked due to multiple failed login attempts. Please try again after 15 minutes.',
            HttpStatusCode.LOCKED
          )
        );
      }
    }

    // Check account lock first
    if (user?.loginAttempts?.lock) {
      const lockTimePassed =
        user.loginAttempts.date &&
        Date.now() - user.loginAttempts.date.getTime() > 15 * 60 * 1000;

      if (!lockTimePassed) {
        res.cookie('x389kld', true, {
          ...cookieOptions,
          ...enableSignature,
          maxAge: 15 * 60 * 1000,
        });
        return next(
          new ApiError(
            'Account locked due to multiple failed login attempts. Please try again after 15 minutes.',
            HttpStatusCode.LOCKED
          )
        );
      }

      // Reset if lock expired
      user.loginAttempts.lock = false;
      user.loginAttempts.attempts = 0;
      user.loginAttempts.date = null;
      await user.save();
    }
  };
}
