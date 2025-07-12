import { CookieOptions, Response } from 'express';
import config from '../../../configs/config';
import ApiError from '../../../middlewares/errors/ApiError';
import HttpStatusCode from '../../../utils/HttpStatusCode';
import { IAuthCookies } from '../types/authTypes';

export const accessTTL: number = parseInt(
  config.ACCESS_TOKEN_EXPIRE ?? '30',
  10
);

export const refreshTTL: number = parseInt(
  config.REFRESH_TOKEN_EXPIRE ?? '3',
  10
);

// 30 min
export const accessCookieExp = {
  expires: new Date(Date.now() + 1 * 60 * 1000),
  maxAge: 1 * 60 * 1000,
};

// 3 days
export const refreshCookieExp = {
  expires: new Date(Date.now() + refreshTTL * 24 * 60 * 60 * 1000),
  maxAge: refreshTTL * 24 * 60 * 60 * 1000,
};

export const enableSignature = {
  signed: true,
};

export const cookieOptions: CookieOptions = {
  httpOnly: true,
  sameSite: 'none',
  secure: true,
  path: '/',
  domain: config.ISPRODUCTION ? '.devmun.xyz' : 'localhost',
};

export class CookieService {
  protected readonly cookies: IAuthCookies;

  constructor(options: { cookies: IAuthCookies }) {
    this.cookies = options.cookies;
  }

  protected getAccessCookieConfig = () => {
    return {
      name: this.cookies.access.name,
      expires: this.cookies.access.TTL,
      options: this.cookies.access.options,
    };
  };

  protected getRefreshCookieConfig = () => {
    return {
      name: this.cookies.refresh.name,
      expires: this.cookies.refresh.TTL,
      options: this.cookies.refresh.options,
    };
  };

  protected clearCookie = (
    res: Response,
    name: string,
    options: CookieOptions
  ) => {
    return res.clearCookie(name, options);
  };

  protected clearAccessCookie = (res: Response): void => {
    this.clearCookie(
      res,
      this.getAccessCookieConfig().name,
      this.getAccessCookieConfig().options
    );
  };

  protected clearRefreshCookie = (res: Response): void => {
    this.clearCookie(
      res,
      this.getRefreshCookieConfig().name,
      this.getRefreshCookieConfig().options
    );
  };

  protected clearAllCookies = (res: Response): void => {
    this.clearAccessCookie(res);
    this.clearRefreshCookie(res);
  };
  protected createAccessCookie = (
    payload: string = '',
    remember: boolean = false
  ): [string, string, CookieOptions] => {
    try {
      const base = this.getAccessCookieConfig();

      const options = remember
        ? { ...base.options, ...base.expires }
        : base.options;

      return [base.name, payload, options];
    } catch {
      throw new ApiError(
        'Failed to create access cookie.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };

  protected createRefreshCookie = (
    payload: string = '',
    remember: boolean = false
  ): [string, string, CookieOptions] => {
    try {
      const base = this.getRefreshCookieConfig();

      const options = remember
        ? { ...base.options, ...base.expires }
        : base.options;

      return [base.name, payload, options];
    } catch {
      throw new ApiError(
        'Failed to create refresh cookie.',
        HttpStatusCode.INTERNAL_SERVER_ERROR
      );
    }
  };
}
