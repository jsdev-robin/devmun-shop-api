import { Schema } from 'mongoose';
import { ISession } from '../../../types/user';

export const SessionSchema = new Schema<ISession>(
  {
    token: String,
    deviceInfo: {
      deviceType: String,
      os: String,
      browser: String,
      userAgent: String,
    },
    location: {
      city: String,
      country: String,
      lat: Number,
      lng: Number,
    },
    ip: String,
    loggedInAt: { type: Date, default: Date.now },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
    },
    revoked: { type: Boolean, default: false },
    revokedAt: Date,
    lastActivityAt: { type: Date, default: Date.now },
    riskScore: { type: Number, default: 0 },
    trustedDevice: { type: Boolean, default: false },
    status: { type: Boolean, default: true },
  },
  { _id: false }
);
