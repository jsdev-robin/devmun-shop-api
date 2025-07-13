import { NextFunction, Request, Response } from 'express';
import rateLimit, { RateLimitRequestHandler } from 'express-rate-limit';
import HttpStatusCode from '../utils/HttpStatusCode';
import ApiError from './errors/ApiError';

export const rateLimiter = ({
  windowMs = 15 * 60 * 1000,
  max = 10000,
  message = 'Too many requests, please try again later.',
}: {
  windowMs?: number;
  max?: number;
  message?: string;
} = {}): RateLimitRequestHandler => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (_req: Request, _res: Response, next: NextFunction) => {
      next(new ApiError(message, HttpStatusCode.TOO_MANY_REQUESTS));
    },
  });
};
