import { NextFunction, Request, Response } from 'express';
import { matchedData, Result, validationResult } from 'express-validator';
import HttpStatusCode from '../../utils/HttpStatusCode';
import ApiError from '../errors/ApiError';

interface ValidationError {
  msg: string;
}

export const runSchema = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errors: Result<ValidationError> = validationResult(req);
  if (!errors.isEmpty()) {
    const error: ApiError = new ApiError(
      errors.array()[0].msg,
      HttpStatusCode.UNPROCESSABLE_ENTITY
    );
    next(error);
    return;
  }

  req.body = matchedData(req, { locations: ['body'] });
  // req.query = matchedData(req, { locations: ['query'] });
  // req.params = matchedData(req, { locations: ['params'] });

  next();
};
