import express from 'express';
import sellerAuthController from '../controllers/sellerController';
import { authSchema } from '../middlewares/validations/auth/authSchema';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.post(
  '/signup',
  authSchema.signup,
  runSchema,
  sellerAuthController.signup
);

export default router;
