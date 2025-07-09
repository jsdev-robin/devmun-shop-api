import {
  CallbackWithoutResultAndOptionalError,
  model,
  Model,
  Schema,
} from 'mongoose';
import slugify from 'slugify';
import { IProduct } from '../../types/product';
import {
  DimensionsSchema,
  MetadataSchema,
  SEOSchema,
  ShippingSchema,
  VariantSchema,
  WarrantySchema,
} from './particles/productSchemas';

const productSchema = new Schema<IProduct>(
  {
    basicInfo: {
      title: { type: String, required: true },
      description: String,
      productType: {
        type: String,
        enum: ['physical', 'digital', 'service', 'bundle'],
        required: true,
      },
      productCode: { type: String, required: true },
    },
    inventory: {
      sku: { type: String, required: true },
      barcode: String,
      batchNumber: String,
      expiryDate: Date,
      warehouseLocation: String,
    },
    pricing: {
      basePrice: { type: Number, required: true },
      salePrice: Number,
      costPrice: Number,
      priceCurrency: String,
      minOrderQuantity: Number,
      maxOrderQuantity: Number,
      taxRate: Number,
      taxInclusive: { type: String, enum: ['include', 'exclude'] },
      taxAmount: Number,
      discountType: { type: String, enum: ['fixed', 'percentage'] },
      discountValue: Number,
      discountStartDate: Date,
      discountEndDate: Date,
      shippingCost: { type: Number, required: true },
      shippingCostType: { type: String, enum: ['fixed', 'calculated'] },
    },
    categories: {
      mainCategory: { type: String, required: true },
      subCategory: { type: String, required: true },
      tertiaryCategory: String,
      productTags: [String],
    },
    attributes: {
      brand: { type: String, required: true },
      manufacturer: String,
      model: String,
      color: String,
      size: String,
      material: String,
      weight: Number,
      dimensions: DimensionsSchema,
      warranty: WarrantySchema,
    },
    variants: [VariantSchema],
    shipping: { type: ShippingSchema },
    seo: { type: SEOSchema },
    metadata: MetadataSchema,
    status: {
      type: String,
      enum: ['draft', 'active', 'archived'],
      required: true,
    },
    isAdult: { type: Boolean, required: true },

    // guides: [
    //   type: mongoose.Schema.ObjectId,
    //   ref: "Seller"
    // ]
  },
  { toJSON: { virtuals: true }, toObject: { virtuals: true }, timestamps: true }
);

productSchema.pre(
  'save',
  function (next: CallbackWithoutResultAndOptionalError) {
    if (this.basicInfo?.title && this.seo) {
      this.seo.slug = slugify(this.basicInfo.title, {
        lower: true,
        strict: true,
        locale: 'en',
        trim: true,
      });
    }
    next();
  }
);

export const productModel: Model<IProduct> = model<IProduct>(
  'Product',
  productSchema
);
