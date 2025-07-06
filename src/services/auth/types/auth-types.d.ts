import { CookieOptions } from 'express';

declare global {
  namespace Express {
    interface Request {
      self: IUser;
      remember: boolean;
      redirect: string;
    }
  }
}

export interface ICookieMeta {
  name: string;
  TTL: {
    expires: Date;
    maxAge: number;
  };
  options: CookieOptions;
}

export interface IAuthCookies {
  access: CookieMeta;
  refresh: CookieMeta;
}
