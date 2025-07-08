import { Document, Types } from 'mongoose';

export type UserRole = 'buyer' | 'seller' | 'admin' | 'moderator';

export interface ILocalizedString {
  [locale: string]: string;
}

export interface IEmail {
  email?: string;
  verified?: boolean;
  verifiedAt?: Date;
  ip: string;
  userAgent: string;
}

export interface IPhoneVerificationHistory {
  attemptedAt?: Date;
  ip?: string;
  userAgent?: string;
  success?: boolean;
}

export interface IPhone {
  countryCode?: string;
  number?: string;
  verified?: boolean;
  verifiedAt?: Date;
  primary?: boolean;
  addedAt?: Date;
  verificationAttempts?: number;
  verificationHistory?: IPhoneVerificationHistory[];
}

export interface IAddress {
  label?: string;
  recipientName?: string;
  company?: string;
  phone?: string;
  streetAddress?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  countryCode?: string;
  geoLocation?: {
    type?: string;
    coordinates?: [number, number]; // [lng, lat]
  };
  isDefault?: boolean;
  addedAt?: Date;
  updatedAt?: Date;
}

export interface ISocialAccount {
  provider?: string;
  providerId?: string;
  email?: string;
  linkedAt?: Date;
  lastLoginAt?: Date;
}

export interface IMFAFactor {
  method?: string;
  enabled?: boolean;
  secret?: string;
  backupCodes?: string[];
  lastUsedAt?: Date;
  enrolledAt?: Date;
}

export interface ISession {
  token?: string;
  deviceInfo?: {
    deviceType?: string;
    os?: string;
    browser?: string;
    userAgent?: string;
  };
  ip?: string;
  location?: {
    city?: string;
    country?: string;
    lat?: number;
    lng?: number;
  };
  loggedInAt?: Date;
  expiresAt?: Date;
  revoked?: boolean;
  revokedAt?: Date;
  lastActivityAt?: Date;
  riskScore?: number;
  trustedDevice?: boolean;
}

export interface INotificationPreference {
  channel?: string;
  event?: string;
  enabled?: boolean;
}

export interface IAccountChangeLog {
  changedAt?: Date;
  changedBy?: Types.ObjectId;
  fieldChanged?: string;
  oldValue?: unknown;
  newValue?: unknown;
  ip?: string;
  userAgent?: string;
}

export interface IBehaviorAnalytics {
  lastPurchaseAt?: Date;
  totalSpent?: number;
  totalOrders?: number;
  avgOrderValue?: number;
  productCategoriesViewed?: {
    categoryId?: Types.ObjectId;
    views?: number;
  }[];
  lastActiveAt?: Date;
}

export interface IComplianceFlags {
  gdprConsent?: boolean;
  gdprConsentAt?: Date;
  ccpaOptOut?: boolean;
  dataExportRequestedAt?: Date;
  dataDeletionRequestedAt?: Date;
  dataDeletionCompletedAt?: Date;
}

export interface IUser extends Document {
  firstName: string;
  lastName: string;
  email?: string;
  normalizeMail?: string;
  password?: string;
  role?: UserRole;
  sessions?: ISession[];
  isActive?: boolean;
  isBanned?: boolean;
  banReason?: string;
  bannedAt?: Date;
  deletedAt?: Date;
  createdAt?: Date;
  updatedAt?: Date;

  isPasswordValid: (candidatePassword: string) => Promise<boolean>;
  incrementLoginAttempts: () => Promise<void>;
  resetLoginAttempts: () => Promise<void>;
}
