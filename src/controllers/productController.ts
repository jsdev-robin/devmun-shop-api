import { productModel } from '../models/products/productModel';
import { ProductServices } from '../services/product/ProductServices';
import { IProduct } from '../types/product';

const productController = new ProductServices<IProduct>(productModel);

export default productController;
