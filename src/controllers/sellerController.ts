import { getUserModel } from '../models/user/userSchema';
import AuthService from '../services/auth/AuthServices';
import { IUser } from '../types/user';
import {
  accessCookieExp,
  cookieOptions,
  enableSignature,
  refreshCookieExp,
} from '../utils/cookieOptions';

const shopAuthController = new AuthService<IUser>({
  model: getUserModel('Seller'),
  cookies: {
    access: {
      name: 'aeuT2k1z9',
      TTL: accessCookieExp,
      options: {
        ...cookieOptions,
        ...enableSignature,
      },
    },
    refresh: {
      name: 'reuT2k1z8',
      TTL: refreshCookieExp,
      options: cookieOptions,
    },
  },
  role: 'seller',
});

export default shopAuthController;
