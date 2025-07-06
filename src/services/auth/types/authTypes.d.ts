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

export interface ISignup {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
}

export interface IVerifyEmail {
  otp: string;
  token: string;
}

export interface ISignin {
  email: string;
  password: string;
  remember: boolean;
}

export interface IPasswordUpdate {
  currentPassword: string;
  newPassword: string;
}

export interface IUpdateEmail {
  newEmail: string;
  password: string;
}
