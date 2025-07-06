import express from 'express';
import config from '../../../configs/config';
import { authSchema } from '../../../middlewares/validations/authSchema';
import { runSchema } from '../../../middlewares/validations/runSchema';
import shopAuthController from '../controllers/shopAuthController';

const router = express.Router();

router.post('/signup', authSchema.signup, runSchema, shopAuthController.signup);
router.post(
  '/verify-email',
  authSchema.verifyEmail,
  runSchema,
  shopAuthController.verifyEmail
);

router.post(
  '/signin',
  authSchema.signin,
  runSchema,
  shopAuthController.signin,
  shopAuthController.createSession()
);

router.post('/refresh-token', shopAuthController.refreshToken);

router.use(
  shopAuthController.validateToken,
  shopAuthController.requireAuth,
  shopAuthController.restrictTo('user', 'admin')
);

router.post('/signout', shopAuthController.signout);
router.post('/sessions/:token/revoke', shopAuthController.signoutSession);
router.post('/sessions/revoke-all', shopAuthController.signoutAllSession);
router.get('/sessions', shopAuthController.getSessions);

// // ================== Manage user information ==================
router
  .route('/me')
  .get(shopAuthController.getProfile)
  .patch(authSchema.profile, runSchema, shopAuthController.updateProfile);

router.get(
  '/me/fields',
  authSchema.getFields,
  runSchema,
  shopAuthController.getProfileFields
);
router.patch(
  '/me/password',
  authSchema.updatePassword,
  runSchema,
  shopAuthController.updatePassword
);
router
  .route('/me/email')
  .post(
    authSchema.updateEmail,
    runSchema,
    shopAuthController.requestEmailUpdate(`${config.SHOP_ORIGIN}/your/account`)
  )
  .patch(authSchema.updatingEmail, runSchema, shopAuthController.updateEmail);

router.patch(
  '/me/preferences',
  authSchema.updateSettings,
  runSchema,
  shopAuthController.updateSettings
);
router
  .route('/me/addresses')
  .patch(authSchema.address, runSchema, shopAuthController.updateAddresses)
  .delete(shopAuthController.deleteAddresses);

router.patch(
  '/me/feedback',
  authSchema.feedback,
  runSchema,
  shopAuthController.updateFeedback
);
export default router;
