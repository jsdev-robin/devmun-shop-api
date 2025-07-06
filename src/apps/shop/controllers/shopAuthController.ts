import AuthService from '../../../services/auth/services/AuthService';
import { IUser } from '../../../types/authTypes';
import {
  accessCookieExp,
  cookieOptions,
  enableSignature,
  refreshCookieExp,
} from '../../../utils/cookieOptions';
import ShopUser from '../models/shopUserModel';

const shopAuthController = new AuthService<IUser>({
  model: ShopUser,
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
  role: 'user',
});

export default shopAuthController;
