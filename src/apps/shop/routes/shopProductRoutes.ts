import express from 'express';
import { productSchema } from '../../../middlewares/validations/product/productSchema';
import { runSchema } from '../../../middlewares/validations/runSchema';
import shopAuthController from '../controllers/shopAuthController';
import shopProductController from '../controllers/shopProductController';

const router = express.Router();

router.use(
  shopAuthController.validateToken,
  shopAuthController.requireAuth,
  shopAuthController.restrictTo('admin', 'seller')
);

router
  .route('/product')
  .post(productSchema, runSchema, shopProductController.create);

export default router;
