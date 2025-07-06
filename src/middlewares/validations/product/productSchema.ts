import { check } from 'express-validator';

export const productSchema = [
  // Basic Info Validation
  check('basicInfo.title')
    .notEmpty()
    .withMessage('Product title is required')
    .isString()
    .withMessage('Title must be a string')
    .isLength({ max: 100 })
    .withMessage('Title too long'),

  check('basicInfo.description')
    .optional()
    .isString()
    .withMessage('Description must be a string')
    .isLength({ max: 3000 })
    .withMessage('Description should be at most 3000 characters'),

  check('basicInfo.productType')
    .notEmpty()
    .withMessage('Product type is required')
    .isIn(['physical', 'digital', 'service', 'bundle'])
    .withMessage('Invalid product type'),

  check('basicInfo.productCode')
    .notEmpty()
    .withMessage('Product code is required')
    .isString()
    .withMessage('Product code must be a string'),

  // Inventory Validation
  check('inventory.sku')
    .notEmpty()
    .withMessage('SKU is required')
    .isString()
    .withMessage('SKU must be a string')
    .isLength({ max: 50 })
    .withMessage('SKU cannot exceed 50 characters'),

  check('inventory.barcode')
    .optional()
    .isString()
    .withMessage('Barcode must be a string')
    .isLength({ max: 50 })
    .withMessage('Barcode cannot exceed 50 characters'),

  check('inventory.batchNumber')
    .optional()
    .isString()
    .withMessage('Batch number must be a string'),

  check('inventory.expiryDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid date format'),

  check('inventory.warehouseLocation')
    .optional()
    .isString()
    .withMessage('Warehouse location must be a string'),

  // Pricing Validation
  check('pricing.basePrice')
    .notEmpty()
    .withMessage('Base price is required')
    .isFloat({ min: 0.01 })
    .withMessage('Base price must be at least 0.01'),

  check('pricing.salePrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Sale price must be at least 0'),

  check('pricing.costPrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Cost price must be at least 0'),

  check('pricing.priceCurrency')
    .optional()
    .isString()
    .withMessage('Price currency must be a string'),

  check('pricing.minOrderQuantity')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Minimum order quantity must be at least 1'),

  check('pricing.maxOrderQuantity')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Maximum order quantity must be at least 1'),

  check('pricing.taxRate')
    .optional()
    .isFloat({ max: 100 })
    .withMessage('Tax rate cannot exceed 100%'),

  check('pricing.taxInclusive')
    .optional()
    .isIn(['include', 'exclude'])
    .withMessage('Invalid tax inclusive value'),

  check('pricing.taxAmount')
    .optional()
    .isFloat()
    .withMessage('Tax amount must be a number'),

  check('pricing.discountType')
    .optional()
    .isIn(['fixed', 'percentage'])
    .withMessage('Invalid discount type'),

  check('pricing.discountValue')
    .optional()
    .isFloat()
    .withMessage('Discount value must be a number'),

  check('pricing.discountStartDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid discount start date format'),

  check('pricing.discountEndDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid discount end date format'),

  check('pricing.shippingCost')
    .notEmpty()
    .withMessage('Shipping cost is required')
    .isFloat()
    .withMessage('Shipping cost must be a number'),

  check('pricing.shippingCostType')
    .optional()
    .isIn(['fixed', 'calculated'])
    .withMessage('Invalid shipping cost type'),

  // Categories Validation
  check('categories.mainCategory')
    .notEmpty()
    .withMessage('Main category is required')
    .isString()
    .withMessage('Main category must be a string'),

  check('categories.subCategory')
    .notEmpty()
    .withMessage('Subcategory is required')
    .isString()
    .withMessage('Subcategory must be a string'),

  check('categories.tertiaryCategory')
    .optional()
    .isString()
    .withMessage('Tertiary category must be a string'),

  check('categories.productTags')
    .optional()
    .isArray()
    .withMessage('Product tags must be an array'),

  check('categories.productTags.*')
    .optional()
    .isString()
    .withMessage('Each product tag must be a string'),

  // Attributes Validation
  check('attributes.brand')
    .notEmpty()
    .withMessage('Brand is required')
    .isString()
    .withMessage('Brand must be a string'),

  check('attributes.manufacturer')
    .optional()
    .isString()
    .withMessage('Manufacturer must be a string'),

  check('attributes.model')
    .optional()
    .isString()
    .withMessage('Model must be a string'),

  check('attributes.color')
    .optional()
    .isString()
    .withMessage('Color must be a string'),

  check('attributes.size')
    .optional()
    .isString()
    .withMessage('Size must be a string'),

  check('attributes.material')
    .optional()
    .isString()
    .withMessage('Material must be a string'),

  check('attributes.weight')
    .optional()
    .isFloat()
    .withMessage('Weight must be a number'),

  // Variants Validation
  check('variants')
    .optional()
    .isArray()
    .withMessage('Variants must be an array'),

  check('variants.*.sku')
    .notEmpty()
    .withMessage('Variant SKU is required')
    .isString()
    .withMessage('Variant SKU must be a string'),

  check('variants.*.color')
    .optional()
    .isString()
    .withMessage('Variant color must be a string'),

  check('variants.*.size')
    .optional()
    .isString()
    .withMessage('Variant size must be a string'),

  check('variants.*.price')
    .notEmpty()
    .withMessage('Variant price is required')
    .isFloat({ min: 0.01 })
    .withMessage('Variant price must be at least 0.01'),

  check('variants.*.costPrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Variant cost price must be at least 0'),

  check('variants.*.salePrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Variant sale price must be at least 0'),

  check('variants.*.stockQuantity')
    .notEmpty()
    .withMessage('Variant stock quantity is required')
    .isNumeric()
    .withMessage('Variant stock quantity must be a number'),

  check('variants.*.barcode')
    .optional()
    .isString()
    .withMessage('Variant barcode must be a string'),

  check('variants.*.weight')
    .optional()
    .isFloat()
    .withMessage('Variant weight must be a number'),

  check('variants.*.isActive')
    .notEmpty()
    .withMessage('Variant active status is required')
    .isBoolean()
    .withMessage('Variant active status must be a boolean'),

  // Shipping Validation
  check('shipping.dimensions.length')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Shipping length must be a positive number'),

  check('shipping.dimensions.width')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Shipping width must be a positive number'),

  check('shipping.dimensions.height')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Shipping height must be a positive number'),

  check('shipping.dimensions.unit')
    .optional()
    .isIn(['cm', 'in', 'm'])
    .withMessage('Invalid dimension unit'),

  check('shipping.shippingClass')
    .optional()
    .isString()
    .withMessage('Shipping class must be a string'),

  check('shipping.isFreeShipping')
    .notEmpty()
    .withMessage('isFreeShipping is required')
    .isBoolean()
    .withMessage('isFreeShipping must be a boolean'),

  check('shipping.requiresShipping')
    .notEmpty()
    .withMessage('requiresShipping is required')
    .isBoolean()
    .withMessage('requiresShipping must be a boolean'),

  // SEO Validation
  check('seo.metaTitle')
    .optional()
    .isString()
    .withMessage('Meta title must be a string'),

  check('seo.metaDescription')
    .optional()
    .isString()
    .withMessage('Meta description must be a string'),

  check('seo.slug').optional().isString().withMessage('Slug must be a string'),
  check('seo.canonicalUrl')
    .optional()
    .isURL()
    .withMessage('Canonical URL must be a valid URL'),

  check('seo.keywords')
    .optional()
    .isArray()
    .withMessage('Keywords must be an array'),

  check('seo.keywords.*')
    .optional()
    .isString()
    .withMessage('Each keyword must be a string'),

  // Status Validation
  check('status')
    .notEmpty()
    .withMessage('Status is required')
    .isIn(['draft', 'active', 'archived'])
    .withMessage('Invalid status'),

  // isAdult Validation
  check('isAdult')
    .notEmpty()
    .withMessage('isAdult is required')
    .isBoolean()
    .withMessage('isAdult must be a boolean'),
];
