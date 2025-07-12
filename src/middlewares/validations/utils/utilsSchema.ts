import { check } from 'express-validator';

export const utilsScham = {
  tempImgPublicIds: [
    check('publicId')
      .isArray({ min: 1 })
      .withMessage('publicId must be a non-empty array'),

    check('publicId.*')
      .isString()
      .withMessage('Each publicId must be a string'),

    check('publicId.*')
      .matches(/^[a-zA-Z0-9_\-/]+$/)
      .withMessage(
        'Each publicId must contain only letters, numbers, underscores, hyphens, or slashes'
      ),
  ],
};
