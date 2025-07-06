import { model, Model } from 'mongoose';
import productModel from '../../../models/product/productModel';
import { IProduct } from '../../../types/productTypes';

const ShopProduct: Model<IProduct> = model<IProduct>(
  'ShopProduct',
  productModel
);

export default ShopProduct;
