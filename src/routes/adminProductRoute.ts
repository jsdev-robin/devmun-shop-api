import express from 'express';
import sellerAuthController from '../controllers/hubAuthController';
import productController from '../controllers/productController';
import { checkMongoId } from '../middlewares/validations/global/global-validator';
import { productSchema } from '../middlewares/validations/products/productSchema';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.use(
  sellerAuthController.validateToken,
  sellerAuthController.requireAuth
);

router
  .route('/product/')
  .get(productController.readAll)
  .post(productSchema, runSchema, productController.create);

// Admin Controller
router
  .route('/product')
  .all(sellerAuthController.restrictTo('admin'))
  .get(productController.readAll)
  .post(productSchema, runSchema, productController.create);

router
  .route('/product/:id')
  .all(sellerAuthController.restrictTo('admin'))
  .get(checkMongoId, runSchema, productController.readOne)
  .delete(checkMongoId, runSchema, productController.deleteOne);

export default router;
