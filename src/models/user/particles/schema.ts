import { Schema, Types } from 'mongoose';
import {
  IAccountChangeLog,
  IAddress,
  IBehaviorAnalytics,
  IComplianceFlags,
  IEmail,
  ILocalizedString,
  IMFAFactor,
  INotificationPreference,
  IPhone,
  IPhoneVerificationHistory,
  ISession,
  ISocialAccount,
} from '../../../types/user';

export const LocalizedStringSchema = new Schema<ILocalizedString>(
  {},
  { _id: false, strict: false }
);

export const EmailSchema = new Schema<IEmail>(
  {
    email: String,
    verified: Boolean,
    verifiedAt: Date,
    ip: String,
    userAgent: String,
  },
  { _id: false }
);

export const PhoneVerificationHistorySchema =
  new Schema<IPhoneVerificationHistory>(
    {
      attemptedAt: Date,
      ip: String,
      userAgent: String,
      success: Boolean,
    },
    { _id: false }
  );

export const PhoneSchema = new Schema<IPhone>(
  {
    countryCode: String,
    number: String,
    verified: Boolean,
    verifiedAt: Date,
    primary: Boolean,
    addedAt: Date,
    verificationAttempts: Number,
    verificationHistory: [PhoneVerificationHistorySchema],
  },
  { _id: false }
);

export const AddressSchema = new Schema<IAddress>(
  {
    label: String,
    recipientName: String,
    company: String,
    phone: String,
    streetAddress: String,
    city: String,
    state: String,
    postalCode: String,
    countryCode: String,
    geoLocation: {
      type: { type: String },
      coordinates: [Number],
    },
    isDefault: Boolean,
    addedAt: Date,
    updatedAt: Date,
  },
  { _id: false }
);

export const SocialAccountSchema = new Schema<ISocialAccount>(
  {
    provider: String,
    providerId: String,
    email: String,
    linkedAt: Date,
    lastLoginAt: Date,
  },
  { _id: false }
);

export const MFAFactorSchema = new Schema<IMFAFactor>(
  {
    method: String,
    enabled: Boolean,
    secret: String,
    backupCodes: [String],
    lastUsedAt: Date,
    enrolledAt: Date,
  },
  { _id: false }
);

export const SessionSchema = new Schema<ISession>(
  {
    token: String,
    deviceInfo: {
      deviceType: String,
      os: String,
      browser: String,
      userAgent: String,
    },
    ip: String,
    location: {
      city: String,
      country: String,
      lat: Number,
      lng: Number,
    },
    loggedInAt: Date,
    expiresAt: Date,
    revoked: Boolean,
    revokedAt: Date,
    lastActivityAt: Date,
    riskScore: Number,
    trustedDevice: Boolean,
  },
  { _id: false }
);

export const NotificationPreferenceSchema = new Schema<INotificationPreference>(
  {
    channel: String,
    event: String,
    enabled: Boolean,
  },
  { _id: false }
);

export const AccountChangeLogSchema = new Schema<IAccountChangeLog>(
  {
    changedAt: Date,
    changedBy: { type: Types.ObjectId, ref: 'User' },
    fieldChanged: String,
    oldValue: Schema.Types.Mixed,
    newValue: Schema.Types.Mixed,
    ip: String,
    userAgent: String,
  },
  { _id: false }
);

export const BehaviorAnalyticsSchema = new Schema<IBehaviorAnalytics>(
  {
    lastPurchaseAt: Date,
    totalSpent: Number,
    totalOrders: Number,
    avgOrderValue: Number,
    productCategoriesViewed: [
      {
        categoryId: { type: Types.ObjectId, ref: 'Category' },
        views: Number,
      },
    ],
    lastActiveAt: Date,
  },
  { _id: false }
);

export const ComplianceFlagsSchema = new Schema<IComplianceFlags>(
  {
    gdprConsent: Boolean,
    gdprConsentAt: Date,
    ccpaOptOut: Boolean,
    dataExportRequestedAt: Date,
    dataDeletionRequestedAt: Date,
    dataDeletionCompletedAt: Date,
  },
  { _id: false }
);
