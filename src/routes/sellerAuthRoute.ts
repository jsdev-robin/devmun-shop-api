import express from 'express';
import sellerAuthController from '../controllers/sellerController';
import { rateLimiter } from '../middlewares/rateLimiter';
import { authSchema } from '../middlewares/validations/auth/authSchema';
import { runSchema } from '../middlewares/validations/runSchema';

const router = express.Router();

router.post(
  '/signup',
  rateLimiter({
    max: 10,
    message:
      'You’ve tried to sign up too many times. Please wait 15 minutes before trying again.',
  }),
  authSchema.signup,
  runSchema,
  sellerAuthController.signup
);

router.post(
  '/verify-email',
  rateLimiter({
    max: 5,
    message:
      'Too many email verification attempts detected. Please wait 15 minutes before trying again.',
  }),
  authSchema.verifyEmail,
  runSchema,
  sellerAuthController.verifyEmail
);

router.post(
  '/signin',
  rateLimiter({
    max: 10,
    message:
      'Too many sign-in attempts. Please wait 15 minutes before trying again.',
  }),
  authSchema.signin,
  runSchema,
  sellerAuthController.accountLock,
  sellerAuthController.signin,
  sellerAuthController.createSession()
);

router.post('/refresh-token', sellerAuthController.refreshToken);

router.use(
  sellerAuthController.validateToken,
  sellerAuthController.requireAuth,
  sellerAuthController.restrictTo('seller', 'admin')
);

router.post('/signout', sellerAuthController.signout);
router.post(
  '/sessions/:token/revoke',
  authSchema.signoutSession,
  runSchema,
  sellerAuthController.signoutSession
);

router.post(
  '/sessions/revoke-all',
  rateLimiter({
    max: 5,
    message:
      'You’ve made too many requests to revoke all sessions. Please wait 15 minutes and try again.',
  }),
  sellerAuthController.signoutAllSession
);

// // ================== Manage user information ==================
router.route('/me').get(sellerAuthController.getProfile);

export default router;
