import { timingSafeEqual } from 'crypto';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import config from '../../../configs/config';
import ApiError from '../../../middlewares/errors/ApiError';
import { UserRole } from '../../../types/user';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { IAuthCookies } from '../types/authTypes';
import { accessTTL, CookieService, refreshTTL } from './CookieService';

export interface TokenSignature {
  ip: string;
  browser: string;
  device: string;
  id: string;
  role: UserRole;
  remember: boolean;
  token: string;
}

export class TokenService extends CookieService {
  constructor(options: { cookies: IAuthCookies }) {
    super(options);
  }
  private tokenSignature(req: Request, user: { id: string; role: string }) {
    return {
      ip: Crypto.hmac(String(req.ip)),
      browser: Crypto.hmac(String(req.useragent?.browser)),
      device: Crypto.hmac(String(req.useragent?.os)),
      id: user.id,
      role: user.role,
    };
  }

  protected checkTokenSignature(
    decoded: TokenSignature | null,
    req: Request
  ): boolean {
    if (!decoded) return true;

    const compare = (a: string, b: string): boolean => {
      const aBuf = Buffer.from(a);
      const bBuf = Buffer.from(b);

      if (aBuf.length !== bBuf.length) return false;
      return timingSafeEqual(aBuf, bBuf);
    };

    return (
      // !compare(decoded.ip, Crypto.hmac(String(req.ip))) ||
      !compare(decoded.device, Crypto.hmac(String(req.useragent?.os))) ||
      !compare(decoded.browser, Crypto.hmac(String(req.useragent?.browser)))
    );
  }

  protected rotateToken = (
    req: Request,
    payload: { id: string; role: string; remember: boolean }
  ): [string, string] => {
    try {
      const { id, role, remember } = payload;

      const clientSignature = this.tokenSignature(req, {
        id: id,
        role: role,
      });

      const accessToken = jwt.sign(
        { ...clientSignature },
        config.ACCESS_TOKEN,
        {
          expiresIn: `${accessTTL}m`,
          algorithm: 'HS256',
        }
      );

      const refreshToken = jwt.sign(
        {
          ...clientSignature,
          remember: remember,
          token: Crypto.hmac(accessToken),
        },
        config.REFRESH_TOKEN,
        {
          expiresIn: `${refreshTTL}d`,
          algorithm: 'HS256',
        }
      );

      return [accessToken, refreshToken];
    } catch {
      throw new ApiError(
        'Failed to generate session tokens. Please try again.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };
}
