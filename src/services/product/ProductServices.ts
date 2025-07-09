import { Request, Response } from 'express';
import { Model } from 'mongoose';
import { catchAsync } from '../../libs/catchAsync';
import { IProduct } from '../../types/product';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';

export class ProductServices<T extends IProduct> {
  private readonly model: Model<T>;

  constructor(model: Model<T>) {
    this.model = model;
  }

  public create = catchAsync(
    async (
      req: Request<unknown, unknown, IProduct>,
      res: Response
    ): Promise<void> => {
      await this.model.create(req.body);

      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Product has been created successfully.',
      });
    }
  );
}
