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
  NameSchema,
  NotificationPreferenceSchema,
  PermissionOverrideSchema,
  PhoneSchema,
  RoleSchema,
  SessionSchema,
  SocialAccountSchema,
} from './particles/schema';

export const UserSchema = new Schema<IUser>(
  {
    name: NameSchema,
    username: String,
    email: String,
    normalizeMail: String,
    password: String,
    primaryPhone: String,
    phones: [PhoneSchema],
    socialAccounts: [SocialAccountSchema],
    roles: [RoleSchema],
    permissionOverrides: [PermissionOverrideSchema],
    mfaFactors: [MFAFactorSchema],
    addresses: [AddressSchema],
    sessions: [SessionSchema],
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

UserSchema.pre('save', function (next) {
  const cap = (str: string) =>
    str ? str.charAt(0).toUpperCase() + str.slice(1).toLowerCase() : '';
  if (this.name?.first && this.name?.last) {
    this.name.full = (cap(this.name.first) + ' ' + cap(this.name.last)).trim();
  }

  next();
});

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

export const getUserModel = (modelName: string = 'User'): Model<IUser> => {
  return model<IUser>(modelName, UserSchema);
};
