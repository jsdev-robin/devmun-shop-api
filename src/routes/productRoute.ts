import express from 'express';
import productController from '../controllers/productController';
import sellerAuthController from '../controllers/sellerController';
import { productSchema } from '../middlewares/validations/products/productSchema';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.use(
  sellerAuthController.validateToken,
  sellerAuthController.requireAuth,
  sellerAuthController.restrictTo('admin', 'seller')
);

router
  .route('/create')
  .post(productSchema, runSchema, productController.create);

export default router;
