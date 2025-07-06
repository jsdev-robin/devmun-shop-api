import { Request } from 'express';
import jwt from 'jsonwebtoken';
import config from '../../../configs/config';
import ApiError from '../../../middlewares/errors/ApiError';
import { Role } from '../../../types/authTypes';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { Crypto } from '../../security/CryptoServices';
import { IAuthCookies } from '../types/auth-types';
import { CookieService } from './CookieService';

export interface TokenSignature {
  ip: string;
  browser: string;
  device: string;
  id: string;
  role: Role;
  remember: boolean;
  token: string;
}

export class TokenService extends CookieService {
  constructor(options: { cookies: IAuthCookies }) {
    super(options);
  }
  private getClientSignature(req: Request, id: string, role: string) {
    return {
      ip: Crypto.hmac(String(req.ip)),
      browser: Crypto.hmac(String(req.useragent?.browser)),
      device: Crypto.hmac(String(req.useragent?.os)),
      id,
      role,
    };
  }

  protected checkClientSignature(
    decoded: TokenSignature | null,
    req: Request
  ): boolean {
    return (
      // decoded?.ip !== Crypto.hmac(String(req.ip)) ||
      decoded?.device !== Crypto.hmac(String(req.useragent?.os)) ||
      decoded?.browser !== Crypto.hmac(String(req.useragent?.browser))
    );
  }

  protected rotateToken(
    req: Request,
    id: string,
    role: string,
    remember: boolean
  ): [string, string] {
    try {
      const clientSignature = this.getClientSignature(req, id, role);

      const accessToken = jwt.sign(
        { ...clientSignature },
        config.ACCESS_TOKEN,
        {
          expiresIn: config.ACCESS_TOKEN_EXPIRE,
          algorithm: 'HS256',
        }
      );

      const refreshToken = jwt.sign(
        { ...clientSignature, remember, token: Crypto.hmac(accessToken) },
        config.REFRESH_TOKEN,
        {
          expiresIn: config.REFRESH_TOKEN_EXPIRE,
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
  }
}
