import { compare, hash } from 'bcryptjs';
import { CallbackWithoutResultAndOptionalError, Schema } from 'mongoose';
import {
  IActivityLog,
  IAddress,
  IFeedback,
  IInclude,
  ISessionToken,
  ISocialConnections,
  IStatus,
  IUser,
} from '../../types/authTypes';

export class AuthSchema {
  protected getIncludeSchema = () =>
    new Schema<IInclude>(
      {
        includeShop: Boolean,
        favoriteItems: Boolean,
        favoriteShops: Boolean,
      },
      { _id: false }
    );

  protected getSettingsSchema = () =>
    new Schema(
      {
        location: {
          region: { type: String },
          language: { type: String },
          currency: { type: String },
        },
        communication: {
          postalMail: { type: Boolean, default: false },
          phoneCalls: { type: Boolean, default: false },
        },
        notifications: {
          send_message: { type: Boolean, default: false },
          receive_reply: { type: Boolean, default: false },
          new_follower: { type: Boolean, default: false },
          listing_expiration: { type: Boolean, default: false },
        },
        subscriptions: {
          new_notable: { type: Boolean, default: false },
          feedback: { type: Boolean, default: false },
          coupons_promotions: { type: Boolean, default: false },
          forums: { type: Boolean, default: false },
          advocacy: { type: Boolean, default: false },
          seller_activity: { type: Boolean, default: false },
          news_features: { type: Boolean, default: false },
          shop_tips: { type: Boolean, default: false },
          pattern_news: { type: Boolean, default: false },
          premium_news: { type: Boolean, default: false },
        },
      },
      { _id: false }
    );

  protected getAddressSchema = () =>
    new Schema<IAddress>({
      country: { type: String },
      fullName: { type: String },
      street: { type: String },
      flat: String,
      city: { type: String },
      postCode: String,
      isDefault: { type: Boolean, default: false },
    });

  protected getFeedbackSchema = () =>
    new Schema<IFeedback>(
      {
        reason: { type: String, required: true },
        subreason: String,
        description: String,
        contractEmail: Boolean,
      },
      { timestamps: true, _id: false }
    );

  protected getSatusSchema = () =>
    new Schema<IStatus>(
      {
        verified: { type: Boolean, default: false },
        isDeactivated: { type: Boolean, default: true },
        banned: { type: Boolean, default: false },
        bannedReason: { type: String },
      },
      { _id: false }
    );

  protected getSessionTokenSchema = () =>
    new Schema<ISessionToken>(
      {
        token: { type: String, required: true },
        device: { type: String },
        ip: { type: String },
        browser: { type: String },
        city: { type: String },
        region: { type: String },
        country: { type: String },
        loc: { type: String },
        org: { type: String },
        postal: { type: String },
        timezone: { type: String },
        status: { type: Boolean, default: true },
        createAt: { type: Date, default: Date.now },
      },
      { _id: false }
    );

  protected getSocialConnectionsSchema = () =>
    new Schema<ISocialConnections>(
      {
        google: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?google\.com\/.+$/.test(v),
            message: 'Invalid Google profile URL',
          },
        },
        facebook: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?facebook\.com\/.+$/.test(v),
            message: 'Invalid Facebook profile URL',
          },
        },
        twitter: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?twitter\.com\/.+$/.test(v),
            message: 'Invalid Twitter profile URL',
          },
        },
        github: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?github\.com\/.+$/.test(v),
            message: 'Invalid GitHub profile URL',
          },
        },
        linkedin: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?linkedin\.com\/in\/.+$/.test(v),
            message: 'Invalid LinkedIn profile URL (must be /in/ profile)',
          },
        },
        instagram: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?instagram\.com\/.+$/.test(v),
            message: 'Invalid Instagram profile URL',
          },
        },
        discord: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) => /^.+#[0-9]{4}$/.test(v),
            message: 'Invalid Discord username (format: username#1234)',
          },
        },
        twitch: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?twitch\.tv\/.+$/.test(v),
            message: 'Invalid Twitch profile URL',
          },
        },
        youtube: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?youtube\.com\/.+$/.test(v),
            message: 'Invalid YouTube channel URL',
          },
        },
        tiktok: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?(www\.)?tiktok\.com\/@.+$/.test(v),
            message: 'Invalid TikTok profile URL (must start with @)',
          },
        },
        spotify: {
          type: String,
          select: false,
          validate: {
            validator: (v: string) =>
              /^(https?:\/\/)?open\.spotify\.com\/user\/.+$/.test(v),
            message: 'Invalid Spotify profile URL',
          },
        },
        _meta: {
          googleId: { type: String, select: false },
          facebookId: { type: String, select: false },
          githubUsername: { type: String, select: false },
          twitterHandle: { type: String, select: false },
          discordId: { type: String, select: false },
        },
      },
      { _id: false }
    );

  protected getActivityLogSchema = () =>
    new Schema<IActivityLog>(
      {
        type: {
          type: String,
          required: true,
          enum: [
            'page_view',
            'click',
            'form_submit',
            'search',
            'login',
            'logout',
            'error',
            'custom_event',
          ],
        },
        path: { type: String, required: true },
        method: {
          type: String,
          enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
          default: 'GET',
        },
        description: { type: String },
        referrer: { type: String },
        userAgent: { type: String },
        ip: { type: String },
        device: { type: String },
        browser: { type: String },
        geo: {
          lat: Number,
          lng: Number,
          accuracy: Number,
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        metadata: {
          type: Object,
        },
      },
      { _id: false }
    );

  private applySchemaMeta = (schema: Schema<IUser>) => {
    // Indexes
    schema.index({ role: 1 });
    schema.index({ city: 1 });

    // Virtual to get user's full name
    schema.virtual('fullName').get(function (this: IUser) {
      return `${this.firstName ?? ''} ${this.lastName ?? ''}`.trim();
    });

    // Hash password before saving
    schema.pre(
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
    schema.methods.isPasswordValid = async function (
      this: IUser,
      candidatePassword: string
    ): Promise<boolean> {
      return await compare(candidatePassword, this.password ?? '');
    };
  };

  public getSchema = () => {
    const schema = new Schema<IUser>(
      {
        firstName: { type: String, trim: true },
        lastName: { type: String, trim: true },
        email: {
          type: String,
          unique: true,
          required: true,
          trim: true,
          lowercase: true,
        },
        normalizeMail: {
          type: String,
          unique: true,
          required: true,
          trim: true,
          lowercase: true,
        },
        password: { type: String, select: false, required: true },
        avatar: {
          public_id: String,
          url: String,
        },
        gender: {
          type: String,
          enum: ['male', 'female', 'other', 'prefer-not-to-say'],
        },
        city: { type: String },
        geo: {
          lat: Number,
          lng: Number,
          accuracy: Number,
          timestamp: Date,
        },
        birthday: { type: Date },
        about: { type: String },
        favoriteMaterials: { type: [String] },
        include: {
          type: this.getIncludeSchema(),
          default: () => ({}),
        },
        role: {
          type: String,
          enum: ['admin', 'user', 'moderator'],
          default: 'user',
        },
        status: {
          type: this.getSatusSchema(),
          select: false,
        },
        lastActive: {
          type: Date,
          default: Date.now,
          select: false,
        },
        sessionToken: {
          type: [this.getSessionTokenSchema()],
          select: false,
        },
        settings: { type: this.getSettingsSchema(), select: false },
        addresses: { type: [this.getAddressSchema()], select: false },
        feedbacks: { type: [this.getFeedbackSchema()], select: false },
        socialConnections: {
          type: [this.getSocialConnectionsSchema()],
          select: false,
        },
        activityLogs: {
          type: [this.getActivityLogSchema()],
          select: false,
          default: [],
        },
      },
      {
        timestamps: true,
        toJSON: {
          virtuals: true,
          transform: (doc, ret) => {
            delete ret.password;
            delete ret.__v;
            return ret;
          },
        },
        toObject: {
          virtuals: true,
          transform: (doc, ret) => {
            delete ret.password;
            delete ret.__v;
            return ret;
          },
        },
      }
    );

    this.applySchemaMeta(schema);

    return schema;
  };
}
