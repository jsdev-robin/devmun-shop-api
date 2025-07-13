import express from 'express';
import utilsController from '../controllers/utilsController';
import { runSchema } from '../middlewares/validations/runSchema';
import { utilsScham } from '../middlewares/validations/utils/utilsSchema';

const router = express.Router();

router
  .route('/temp-img')
  .post(utilsScham.tempImgPublicIds, runSchema, utilsController.setTempImg)
  .get(utilsController.deleteTempImg);

router.route('/temp-img/:id').delete(utilsController.deleteTempImgById);

router.route('/sessions').get(utilsController.removeAlSessions);

export default router;
