import { Model } from 'mongoose';
import { IUser, UserRole } from '../../types/user';
import { AuthServiceOptions } from './types/authTypes';

export class AuthServices<T extends IUser> {
  private readonly model: Model<T>;
  private readonly role: UserRole;

  constructor(options: AuthServiceOptions<T>) {
    this.model = options.model;
    this.role = options.role;
  }
}

export default AuthServices;
