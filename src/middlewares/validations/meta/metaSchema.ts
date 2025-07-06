import { check, ValidationChain } from 'express-validator';

export const metaSchemaPOST: ValidationChain[] = [
  check('country.label')
    .optional()
    .notEmpty()
    .withMessage('Country label is required')
    .isString()
    .withMessage('Country label must be a string'),

  check('country.value')
    .optional()
    .notEmpty()
    .withMessage('Country value is required')
    .isString()
    .withMessage('Country value must be a string'),

  check('currency.label')
    .optional()
    .notEmpty()
    .withMessage('Currency label is required')
    .isString()
    .withMessage('Currency label must be a string'),

  check('currency.value')
    .optional()
    .notEmpty()
    .withMessage('Currency value is required')
    .isString()
    .withMessage('Currency value must be a string'),

  check('language.label')
    .optional()
    .notEmpty()
    .withMessage('Language label is required')
    .isString()
    .withMessage('Language label must be a string'),

  check('language.value')
    .optional()
    .notEmpty()
    .withMessage('Language value is required')
    .isString()
    .withMessage('Language value must be a string'),
];

const metaSchmea = {
  metaSchemaPOST,
};

export default metaSchmea;
