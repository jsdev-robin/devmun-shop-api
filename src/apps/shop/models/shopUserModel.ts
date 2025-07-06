import { model, Model } from 'mongoose';
import { authModel } from '../../../models/auth/AuthModel';
import { IUser } from '../../../types/authTypes';

const ShopUser: Model<IUser> = model<IUser>('ShopUser', authModel);

export default ShopUser;
