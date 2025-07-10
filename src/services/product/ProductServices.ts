import { NextFunction, Request, Response } from 'express';
import { Model } from 'mongoose';
import { catchAsync } from '../../libs/catchAsync';
import ApiError from '../../middlewares/errors/ApiError';
import { IProduct } from '../../types/product';
import HttpStatusCode from '../../utils/HttpStatusCode';
import Status from '../../utils/status';
import { QueryServices } from '../features/QueryServices';

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
      await this.model.create({
        ...req.body,
        guides: req.self._id,
      });

      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message: 'Product has been created successfully.',
      });
    }
  );

  public createMany = catchAsync(
    async (
      req: Request<unknown, unknown, IProduct[]>,
      res: Response
    ): Promise<void> => {
      const productsWithGuide = req.body.map((product) => ({
        ...product,
        guides: req.self._id,
      }));

      await this.model.insertMany(productsWithGuide);

      res.status(HttpStatusCode.CREATED).json({
        status: Status.SUCCESS,
        message: 'Products have been created successfully.',
      });
    }
  );

  public readAll = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      // 1. Pagination
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const skip = (page - 1) * limit;

      if (page < 1 || limit < 1) {
        return next(
          new ApiError(
            'Page and limit must be positive integers',
            HttpStatusCode.BAD_REQUEST
          )
        );
      }

      // 2. Field selection
      const fields =
        (req.query.fields as string)
          ?.split(',')
          .filter((field) => /^[a-zA-Z0-9_-]+$/.test(field))
          .join(' ') || '-__v';

      // 3. Sorting
      const sortBy =
        (req.query.sort as string)?.split(',')?.join(' ') || '-createdAt';

      // 4. Filtering
      const queryObj = { ...req.query };
      const excludedFields = ['page', 'limit', 'sort', 'fields'];
      excludedFields.forEach((el) => delete queryObj[el]);

      // Advanced filtering
      let queryStr = JSON.stringify(queryObj);
      queryStr = queryStr.replace(
        /\b(gte|gt|lte|lt)\b/g,
        (match) => `$${match}`
      );

      // 5. Build query
      const baseQuery = this.model
        .find({
          ...JSON.parse(queryStr),
          _id: { $ne: req.self?._id },
        })
        .populate({
          path: 'guides',
          select: 'firstName lastName email -_id',
        });

      // 6. Execute queries
      const [products, total] = await Promise.all([
        baseQuery
          .clone()
          .select(fields)
          .sort(sortBy)
          .skip(skip)
          .limit(limit)
          .lean()
          .exec(),
        this.model.countDocuments(baseQuery.getFilter()),
      ]);

      // 7. Handle no products found
      if (products.length === 0) {
        return next(
          new ApiError(
            'No products found matching the specified criteria',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Product has been retrieve successfully.',
        data: {
          products,
          pagination: {
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            itemsPerPage: limit,
            hasNextPage: page < Math.ceil(total / limit),
            hasPrevPage: page > 1,
            nextPage: page < Math.ceil(total / limit) ? page + 1 : null,
            prevPage: page > 1 ? page - 1 : null,
          },
        },
      });
    }
  );

  public readOne = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const product = await this.model.findById(req.params.id);

      if (!product) {
        return next(
          new ApiError(
            'No product found with the specified ID',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Product has been created successfully.',
        data: {
          product,
        },
      });
    }
  );

  public deleteOne = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const product = await this.model.findByIdAndDelete(req.params.id);

      if (!product) {
        return next(
          new ApiError(
            'No product found with the specified ID',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      res.status(HttpStatusCode.NO_CONTENT).end();
    }
  );

  public readMyAll = catchAsync(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;

      const features = new QueryServices(this.model, req.query)
        .filter()
        .sort()
        .limitFields()
        .paginate()
        .populate({
          path: 'guides',
          select: 'firstName lastName email -_id',
        });

      const { data, total } = await features.exec();

      // 7. Handle no products found
      if (data.length === 0) {
        return next(
          new ApiError(
            'No products found matching the specified criteria',
            HttpStatusCode.NOT_FOUND
          )
        );
      }

      res.status(HttpStatusCode.OK).json({
        status: Status.SUCCESS,
        message: 'Product has been retrieve successfully.',
        data: {
          data,
          total,
          pagination: {
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            itemsPerPage: limit,
            hasNextPage: page < Math.ceil(total / limit),
            hasPrevPage: page > 1,
            nextPage: page < Math.ceil(total / limit) ? page + 1 : null,
            prevPage: page > 1 ? page - 1 : null,
          },
        },
      });
    }
  );
}
