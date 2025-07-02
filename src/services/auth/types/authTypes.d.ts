import { CookieOptions } from 'express';
import { UserRole } from '../../../types/user';

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

export interface AuthServiceOptions<T> {
  model: Model<T>;
  cookies: IAuthCookies;
  role: UserRole;
}
