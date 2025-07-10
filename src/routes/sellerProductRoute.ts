import express from 'express';
import productController from '../controllers/productController';
import sellerAuthController from '../controllers/sellerController';
import { checkMongoId } from '../middlewares/validations/global/global-validator';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.use(
  sellerAuthController.validateToken,
  sellerAuthController.requireAuth,
  sellerAuthController.restrictTo('admin', 'seller')
);

router
  .route('/product')
  .get(productController.readMyAll)
  .post(productController.createMany);

router
  .route('/product/:id')
  .get(checkMongoId, runSchema, productController.readOne)
  .delete(checkMongoId, runSchema, productController.deleteOne);

export default router;
