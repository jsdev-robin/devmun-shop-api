import express from 'express';
import hubAuthController from '../controllers/hubAuthController';
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
  hubAuthController.signup
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
  hubAuthController.verifyEmail
);

router.post(
  '/signin',
  rateLimiter({
    max: 500,
    message:
      'Too many sign-in attempts. Please wait 15 minutes before trying again.',
  }),
  authSchema.signin,
  runSchema,
  hubAuthController.accountLock,
  hubAuthController.signin,
  hubAuthController.createSession()
);

router.post('/refresh-token', hubAuthController.refreshToken);

router.use(
  hubAuthController.validateToken,
  hubAuthController.requireAuth,
  hubAuthController.restrictTo('seller', 'admin')
);

router.post('/signout', hubAuthController.signout);
router.post(
  '/sessions/:token/revoke',
  authSchema.signoutSession,
  runSchema,
  hubAuthController.signoutSession
);

router.post(
  '/sessions/revoke-all',
  rateLimiter({
    max: 5,
    message:
      'You’ve made too many requests to revoke all sessions. Please wait 15 minutes and try again.',
  }),
  hubAuthController.signoutAllSession
);

// // ================== Manage user information ==================
router.route('/me').get(hubAuthController.getProfile);

router.get(
  '/me/fields',
  authSchema.getFields,
  runSchema,
  hubAuthController.getProfileFields
);

export default router;
