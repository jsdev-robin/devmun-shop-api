import { CookieOptions } from 'express';
import config from '../../../configs/config';
import { IAuthCookies } from '../types/authTypes';

export const accessTTL: number = parseInt(
  config.ACCESS_TOKEN_EXPIRE ?? '3',
  10
);

export const refreshTTL: number = parseInt(
  config.REFRESH_TOKEN_EXPIRE ?? '5',
  10
);

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
}
