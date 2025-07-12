import { getUserModel } from '../models/user/userSchema';
import AuthServices from '../services/auth/AuthServices';
import {
  cookieOptions,
  enableSignature,
  refreshCookieExp,
} from '../services/auth/particles/CookieService';
import { AuthServiceOptions } from '../services/auth/types/authTypes';
import { IUser } from '../types/user';

const options: AuthServiceOptions<IUser> = {
  model: getUserModel('Seller'),
  cookies: {
    access: {
      name: 'aeuT2k1z9',
      TTL: refreshCookieExp,
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

const hubAuthController = new AuthServices<IUser>(options);

export default hubAuthController;
