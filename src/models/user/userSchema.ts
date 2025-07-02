import { model, Model, Schema } from 'mongoose';
import { IUser } from '../../types/user';
import {
  AccountChangeLogSchema,
  AddressSchema,
  BehaviorAnalyticsSchema,
  ComplianceFlagsSchema,
  EmailSchema,
  LoginAttemptSchema,
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
    emails: [EmailSchema],
    phones: [PhoneSchema],
    primaryEmail: String,
    primaryPhone: String,
    passwordHash: String,
    passwordSalt: String,
    socialAccounts: [SocialAccountSchema],
    roles: [RoleSchema],
    permissionOverrides: [PermissionOverrideSchema],
    mfaFactors: [MFAFactorSchema],
    addresses: [AddressSchema],
    sessions: [SessionSchema],
    notificationPreferences: [NotificationPreferenceSchema],
    loginAttempts: [LoginAttemptSchema],
    accountChangeLogs: [AccountChangeLogSchema],
    behaviorAnalytics: BehaviorAnalyticsSchema,
    complianceFlags: ComplianceFlagsSchema,
    isActive: Boolean,
    isBanned: Boolean,
    banReason: String,
    bannedAt: Date,
    deletedAt: Date,
  },
  { timestamps: true }
);

export const getUserModel = (modelName: string = 'User'): Model<IUser> => {
  return model<IUser>(modelName, UserSchema);
};
