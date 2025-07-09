import { Schema } from 'mongoose';
import {
  IDimensions,
  IProductMetadata,
  ISEO,
  IShipping,
  IVariant,
  IWarranty,
} from '../../../types/product';

// Sub-schemas
export const DimensionsSchema = new Schema<IDimensions>(
  {
    length: Number,
    width: Number,
    height: Number,
    unit: { type: String, enum: ['cm', 'in', 'm'], required: true },
  },
  { _id: false }
);

export const WarrantySchema = new Schema<IWarranty>(
  {
    period: Number,
    unit: { type: String, enum: ['days', 'months', 'years'] },
    terms: String,
  },
  { _id: false }
);

export const VariantSchema = new Schema<IVariant>(
  {
    sku: { type: String, required: true },
    color: String,
    size: String,
    price: { type: Number, required: true },
    costPrice: Number,
    salePrice: Number,
    stockQuantity: { type: Number, required: true },
    barcode: String,
    weight: Number,
    isActive: { type: Boolean, required: true },
  },
  { _id: false }
);

export const ShippingSchema = new Schema<IShipping>(
  {
    dimensions: DimensionsSchema,
    shippingClass: String,
    isFreeShipping: { type: Boolean, required: true },
    requiresShipping: { type: Boolean, required: true },
  },
  { _id: false }
);

export const SEOSchema = new Schema<ISEO>({
  metaTitle: String,
  metaDescription: String,
  slug: String,
  canonicalUrl: String,
  keywords: [String],
});

export const MetadataSchema = new Schema<IProductMetadata>(
  {
    notes: { type: String, required: true },
    featured: { type: Boolean, required: true },
    createdBy: { type: String },
    updatedBy: { type: String },
    rating: { type: Number, min: 0, max: 5 },

    tags: [String],
    badges: {
      type: [String],
      enum: ['new', 'sale', 'bestseller', 'exclusive', 'limited', 'eco'],
    },

    flashDeal: {
      isActive: { type: Boolean },
      discountType: { type: String, enum: ['fixed', 'percentage'] },
      discountValue: { type: Number },
      startDate: { type: Date },
      endDate: { type: Date },
    },

    launchCampaign: {
      id: { type: String },
      title: { type: String },
      bannerUrl: { type: String },
      status: { type: String, enum: ['upcoming', 'active', 'expired'] },
      regions: [String],
      startDate: { type: Date },
      endDate: { type: Date },
    },

    features: [
      {
        label: { type: String },
        icon: { type: String },
        value: { type: String },
        highlight: { type: Boolean },
      },
    ],

    uiPreferences: {
      showStockStatus: { type: Boolean },
      showCountdown: { type: Boolean },
      displayBadgeOnImage: { type: Boolean },
      customCssClass: { type: String },
    },

    marketing: {
      facebookPixelId: { type: String },
      googleAnalyticsId: { type: String },
      utmParams: {
        type: Map,
        of: String,
      },
    },

    personalization: {
      userGroupVisibility: [String],
      genderTargeting: {
        type: String,
        enum: ['male', 'female', 'all'],
      },
      languageVariants: [String],
    },

    abTestConfig: {
      testId: { type: String },
      variants: [String],
      active: { type: Boolean },
    },

    flags: {
      isBeta: { type: Boolean },
      isHidden: { type: Boolean },
      isBackorderEnabled: { type: Boolean },
      isLowInventoryAlert: { type: Boolean },
    },
  },
  { _id: false }
);
