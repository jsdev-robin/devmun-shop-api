import { randomInt } from 'crypto';
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import config from '../../../configs/config';
import { nodeClient } from '../../../configs/redis';
import ApiError from '../../../middlewares/errors/ApiError';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { cookieOptions, enableSignature } from './CookieService';
import { TokenService } from './TokenService';

export class AuthEngine extends TokenService {
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
}
