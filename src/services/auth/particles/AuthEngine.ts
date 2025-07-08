import { randomInt } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { Model } from 'mongoose';
import config from '../../../configs/config';
import { nodeClient } from '../../../configs/redis';
import ApiError from '../../../middlewares/errors/ApiError';
import { IUser } from '../../../types/user';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { cookieOptions, enableSignature, refreshTTL } from './CookieService';
import { TokenService } from './TokenService';

export class AuthEngine extends TokenService {
  protected getDeviceInfo = (req: Request) => {
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

  protected getLocationInfo = (req: Request) => ({
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

  protected enforceLockPolicy = async (
    res: Response,
    payload: {
      key: string;
      TTL: number;
    }
  ): Promise<void> => {
    try {
      const { key, TTL = 1 } = payload;
      const hashedKey = Crypto.hash(key);
      const p = nodeClient.multi();
      p.INCR(hashedKey);
      await p.expire(hashedKey, TTL * 15 * 60);
      const [incr] = await p.exec();

      if (incr && Number(incr) >= 5) {
        res.cookie('x389kld', hashedKey, {
          ...cookieOptions,
          ...enableSignature,
          maxAge: TTL * 15 * 60 * 1000,
        });

        res.cookie('lockTime', TTL, {
          ...cookieOptions,
          ...enableSignature,
          maxAge: TTL * 15 * 60 * 1000,
        });
      }
    } catch {
      throw new ApiError(
        'Temporary system issue - please try again in a moment',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected storeSession = async <T extends { _id: string | number }>(
    req: Request,
    Model: Model<T>,
    payload: {
      user: T;
      accessToken: string;
    }
  ): Promise<void> => {
    try {
      const { user, accessToken } = payload;
      const id = user._id;
      const hashedToken = Crypto.hmac(String(accessToken));

      await Promise.all([
        // Redis operations
        (async () => {
          const p = nodeClient.multi();
          p.SADD(`${id}:session`, hashedToken);
          p.json.SET(`${id}`, '$', user);
          p.EXPIRE(`${id}:session`, refreshTTL * 24 * 60 * 60);
          p.EXPIRE(`${id}`, refreshTTL * 24 * 60 * 60);
          await p.exec();
        })(),

        // MongoDB operations
        Model.findByIdAndUpdate(
          id,
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
        'Failed to store session',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected rotateSession = async <T extends IUser>(
    Model: Model<T>,
    payload: {
      id: string;
      oldToken: string;
      newToken: string;
    }
  ): Promise<void> => {
    try {
      const { id, oldToken, newToken } = payload;
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
        Model.findByIdAndUpdate(
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
        ).exec(),
      ]);
    } catch {
      throw new ApiError(
        'Failed to rotate session. Please try again later.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected removeASession = async <T extends IUser>(
    res: Response,
    Model: Model<T>,
    payload: {
      id: string;
      token: string;
    }
  ): Promise<void> => {
    try {
      const { id, token } = payload;
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
        Model.findByIdAndUpdate(
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
        ).exec(),
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

  protected sessionUnauthorized = (res: Response, next: NextFunction) => {
    this.clearAllCookies(res);
    return next(
      new ApiError(
        'Your session has expired or is no longer available. Please log in again to continue.',
        HttpStatusCode.UNAUTHORIZED
      )
    );
  };
}
