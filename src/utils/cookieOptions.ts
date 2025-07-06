import { CookieOptions } from 'express';
import config from '../configs/config';

// Expiration time for access token in minutes.
export const accessTTL: number = parseInt(
  config.ACCESS_TOKEN_EXPIRE ?? '3',
  10
);

// Expiration time for refresh token in days.
export const refreshTTL: number = parseInt(
  config.REFRESH_TOKEN_EXPIRE ?? '5',
  10
);

//  Common options for cookie settings.
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

//  Options for access token cookie. 20 minutes
// export const accessCookieExp = {
//   expires: new Date(Date.now() + 15 * 1000),
//   maxAge: 15 * 1000,
// };

// For Testing
export const accessCookieExp = {
  expires: new Date(Date.now() + refreshTTL * 24 * 60 * 60 * 1000),
  maxAge: refreshTTL * 24 * 60 * 60 * 1000,
};

// 3 days
export const refreshCookieExp = {
  expires: new Date(Date.now() + refreshTTL * 24 * 60 * 60 * 1000),
  maxAge: refreshTTL * 24 * 60 * 60 * 1000,
};
