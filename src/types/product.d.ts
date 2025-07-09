import { Document } from 'mongoose';

interface IDimensions {
  length?: number;
  width?: number;
  height?: number;
  unit: 'cm' | 'in' | 'm';
}

interface IWarranty {
  period?: number;
  unit?: 'days' | 'months' | 'years';
  terms?: string;
}

interface IVariant {
  sku: string;
  color?: string;
  size?: string;
  price: number;
  costPrice?: number;
  salePrice?: number;
  stockQuantity: number;
  barcode?: string;
  weight?: number;
  isActive: boolean;
}

interface IShipping {
  dimensions?: IDimensions;
  shippingClass?: string;
  isFreeShipping: boolean;
  requiresShipping: boolean;
}

interface ISEO {
  metaTitle?: string;
  metaDescription?: string;
  slug?: string;
  canonicalUrl?: string;
  keywords?: string[];
}

interface IProductMetadata {
  notes: string;
  featured: boolean;
  createdBy?: string;
  updatedBy?: string;
  rating?: number;

  tags?: string[];
  badges?: ('new' | 'sale' | 'bestseller' | 'exclusive' | 'limited' | 'eco')[];

  flashDeal?: {
    isActive: boolean;
    discountType: 'fixed' | 'percentage';
    discountValue: number;
    startDate: Date;
    endDate: Date;
  };

  launchCampaign?: {
    id: string;
    title: string;
    bannerUrl?: string;
    status: 'upcoming' | 'active' | 'expired';
    regions?: string[];
    startDate: Date;
    endDate: Date;
  };

  features?: Array<{
    label: string;
    icon?: string;
    value: string;
    highlight?: boolean;
  }>;

  uiPreferences?: {
    showStockStatus?: boolean;
    showCountdown?: boolean;
    displayBadgeOnImage?: boolean;
    customCssClass?: string;
  };

  marketing?: {
    facebookPixelId?: string;
    googleAnalyticsId?: string;
    utmParams?: Record<string, string>;
  };

  personalization?: {
    userGroupVisibility?: string[];
    genderTargeting?: 'male' | 'female' | 'all';
    languageVariants?: string[];
  };

  abTestConfig?: {
    testId: string;
    variants: string[];
    active: boolean;
  };

  flags?: {
    isBeta?: boolean;
    isHidden?: boolean;
    isBackorderEnabled?: boolean;
    isLowInventoryAlert?: boolean;
  };
}

// Main Product Interface
export interface IProduct extends Document {
  basicInfo: {
    title: string;
    description?: string;
    productType: 'physical' | 'digital' | 'service' | 'bundle';
    productCode: string;
  };
  inventory: {
    sku: string;
    barcode?: string;
    batchNumber?: string;
    expiryDate?: Date;
    warehouseLocation?: string;
  };
  pricing: {
    basePrice: number;
    salePrice?: number;
    costPrice?: number;
    priceCurrency?: string;
    minOrderQuantity?: number;
    maxOrderQuantity?: number;
    taxRate?: number;
    taxInclusive?: 'include' | 'exclude';
    taxAmount?: number;
    discountType?: 'fixed' | 'percentage';
    discountValue?: number;
    discountStartDate?: Date;
    discountEndDate?: Date;
    shippingCost: number;
    shippingCostType?: 'fixed' | 'calculated';
  };
  categories: {
    mainCategory: string;
    subCategory: string;
    tertiaryCategory?: string;
    productTags?: string[];
  };
  attributes: {
    brand: string;
    manufacturer?: string;
    model?: string;
    color?: string;
    size?: string;
    material?: string;
    weight?: number;
    dimensions?: IDimensions;
    warranty?: IWarranty;
  };
  variants?: IVariant[];
  shipping?: IShipping;
  seo?: ISEO;
  metadata: IProductMetadata;
  status: 'draft' | 'active' | 'archived';
  isAdult: boolean;
}
