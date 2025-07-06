import { ProductServices } from '../../../services/product/ProductServices';
import { IProduct } from '../../../types/productTypes';
import ShopProduct from '../models/shopProductModel';

const shopProductController = new ProductServices<IProduct>(ShopProduct);

export default shopProductController;
