import express from 'express';
import hubAuthController from '../controllers/hubAuthController';
import productController from '../controllers/productController';
import { checkMongoId } from '../middlewares/validations/global/global-validator';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.use(
  hubAuthController.validateToken,
  hubAuthController.requireAuth,
  hubAuthController.restrictTo('admin', 'seller')
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
