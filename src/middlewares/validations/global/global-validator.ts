import { param } from 'express-validator';

export const checkMongoId = [
  param('id')
    .notEmpty()
    .withMessage('ID is required')
    .isMongoId()
    .withMessage('Invalid MongoDB ObjectId'),
];
