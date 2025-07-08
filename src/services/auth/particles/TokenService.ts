import { UserRole } from '../../../types/user';
import { IAuthCookies } from '../types/authTypes';
import { CookieService } from './CookieService';

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
}
