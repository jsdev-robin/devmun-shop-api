import { compare, hash } from 'bcryptjs';
import {
  CallbackWithoutResultAndOptionalError,
  model,
  Model,
  Schema,
} from 'mongoose';
import { IUser } from '../../types/user';
import {
  AccountChangeLogSchema,
  AddressSchema,
  BehaviorAnalyticsSchema,
  ComplianceFlagsSchema,
  EmailSchema,
  MFAFactorSchema,
  NotificationPreferenceSchema,
  PermissionOverrideSchema,
  PhoneSchema,
  RoleSchema,
  SessionSchema,
  SocialAccountSchema,
} from './particles/schema';

export const UserSchema = new Schema<IUser>(
  {
    firstName: String,
    lastName: String,
    email: {
      type: String,
      unique: true,
    },
    normalizeMail: {
      type: String,
      unique: true,
      select: false,
    },
    password: String,
    primaryPhone: String,
    phones: [PhoneSchema],
    socialAccounts: [SocialAccountSchema],
    roles: [RoleSchema],
    permissionOverrides: [PermissionOverrideSchema],
    mfaFactors: [MFAFactorSchema],
    addresses: [AddressSchema],
    sessions: {
      type: [SessionSchema],
      select: false,
    },
    notificationPreferences: [NotificationPreferenceSchema],
    accountChangeLogs: [AccountChangeLogSchema],
    behaviorAnalytics: BehaviorAnalyticsSchema,
    complianceFlags: ComplianceFlagsSchema,
    emailChangeLog: {
      type: [EmailSchema],
      select: false,
    },
    isActive: Boolean,
    isBanned: Boolean,
    banReason: String,
    bannedAt: Date,
    deletedAt: Date,
  },
  { timestamps: true }
);

// Hash password before saving
UserSchema.pre(
  'save',
  async function (next: CallbackWithoutResultAndOptionalError) {
    try {
      if (!this.isModified('password')) return next();
      this.password = await hash(this.password ?? '', 12);

      next();
    } catch (error: unknown) {
      next(error as Error);
    }
  }
);

// Validate provided password with stored hash
UserSchema.methods.isPasswordValid = async function (
  this: IUser,
  candidatePassword: string
): Promise<boolean> {
  return await compare(candidatePassword, this.password ?? '');
};

// where UserSchema is defined
UserSchema.methods.incrementLoginAttempts = async function (): Promise<void> {
  if (!this.loginAttempts) {
    this.loginAttempts = { attempts: 0, lock: false, date: null };
  }
  this.loginAttempts.attempts += 1;

  if (this.loginAttempts.attempts >= 5) {
    this.loginAttempts.lock = true;
    this.loginAttempts.date = new Date();
  }
  await this.save();
};

UserSchema.methods.resetLoginAttempts = async function (): Promise<void> {
  this.loginAttempts = {
    attempts: 0,
    lock: false,
    date: null,
  };
  await this.save();
};

export const getUserModel = (modelName: string = 'User'): Model<IUser> => {
  return model<IUser>(modelName, UserSchema);
};
