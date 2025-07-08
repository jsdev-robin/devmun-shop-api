import { getUserModel } from '../models/user/userSchema';
import AuthServices from '../services/auth/AuthServices';
import {
  cookieOptions,
  enableSignature,
} from '../services/auth/particles/CookieService';
import { AuthServiceOptions } from '../services/auth/types/authTypes';
import { IUser } from '../types/user';
import { accessCookieExp, refreshCookieExp } from '../utils/cookieOptions';

const options: AuthServiceOptions<IUser> = {
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
};

const sellerAuthController = new AuthServices<IUser>(options);

export default sellerAuthController;
