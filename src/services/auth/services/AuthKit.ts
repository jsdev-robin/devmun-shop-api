import { randomInt } from 'crypto';
import { NextFunction, Request, Response } from 'express';
import { promises as fs } from 'fs';
import jwt from 'jsonwebtoken';
import { Model } from 'mongoose';
import cloudinary from '../../../configs/cloudinary';
import config from '../../../configs/config';
import { nodeClient } from '../../../configs/redis';
import ApiError from '../../../middlewares/errors/ApiError';
import { IUser } from '../../../types/authTypes';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { refreshTTL } from './CookieService';
import { TokenService } from './TokenService';

export class AuthKit extends TokenService {
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
              sessionToken: {
                token: hashedToken,
                device: req.useragent?.os ?? 'unknown',
                ip: req.ip ?? 'unknown',
                browser: req.useragent?.browser ?? 'unknown',
                location: req.ipinfo?.location ?? 'unknown',
                city: req.ipinfo?.city ?? 'unknown',
                region: req.ipinfo?.region ?? 'unknown',
                country: req.ipinfo?.country ?? 'unknown',
                loc: req.ipinfo?.loc ?? 'unknown',
                org: req.ipinfo?.org ?? 'unknown',
                postal: req.ipinfo?.postal ?? 'unknown',
                timezone: req.ipinfo?.timezone ?? 'unknown',
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

  protected uploadAvatar = async (req: Request) => {
    if (req.file) {
      const id = `user-avatar_${Crypto.hmac(req.self?._id)}`;
      const path = req.file.path;

      try {
        const [, result] = await Promise.all([
          cloudinary.uploader.destroy(id, {
            resource_type: 'image',
          }),
          cloudinary.uploader.upload(path, {
            folder: 'user-avatar',
            public_id: id,
            use_filename: true,
            unique_filename: false,
            overwrite: true,
            resource_type: 'image',
          }),
        ]);

        await fs
          .unlink(path)
          .catch((err) => console.error('Failed to delete temp file:', err));

        const avatar = {
          url: result.secure_url,
          public_id: result.public_id,
        };

        return avatar;
      } catch (error) {
        await fs
          .unlink(path)
          .catch((err) =>
            console.error('Failed to delete temp file after error:', err)
          );
        throw error;
      }
    }
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
}
