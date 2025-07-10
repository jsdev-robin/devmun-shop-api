import { Document, Model, PopulateOptions, Query } from 'mongoose';
import QueryString from 'qs';

export class QueryServices<T extends Document> {
  private query: Query<T[], T>;
  private queryString: QueryString.ParsedQs;

  constructor(model: Model<T>, queryString: QueryString.ParsedQs) {
    this.query = model.find();
    this.queryString = queryString;
  }

  public filter(): this {
    const queryObj = { ...this.queryString };
    const excludedFields = ['page', 'limit', 'sort', 'fields'];
    excludedFields.forEach((el) => delete queryObj[el]);

    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`);

    const parsedQuery = JSON.parse(queryStr);

    Object.entries(parsedQuery).forEach(([key, value]) => {
      if (typeof value === 'string') {
        parsedQuery[key] = { $regex: value, $options: 'i' };
      }
    });

    this.query = this.query.find(parsedQuery);
    return this;
  }

  public sort(): this {
    if (this.queryString.sort) {
      const sortBy =
        typeof this.queryString.sort === 'string'
          ? this.queryString.sort.split(',').join(' ')
          : Array.isArray(this.queryString.sort)
          ? this.queryString.sort.join(' ').split(',').join(' ')
          : '-createdAt';
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort('-createdAt');
    }
    return this;
  }

  public limitFields(): this {
    if (this.queryString.fields) {
      const fields =
        typeof this.queryString.fields === 'string'
          ? this.queryString.fields.split(',').join(' ')
          : Array.isArray(this.queryString.fields)
          ? this.queryString.fields.join(' ').split(',').join(' ')
          : '-__v';
      this.query = this.query.select(fields);
    } else {
      this.query = this.query.select('-__v');
    }
    return this;
  }

  public paginate(): this {
    const page = this.queryString.page
      ? parseInt(String(this.queryString.page), 20) || 1
      : 1;
    const limit = this.queryString.limit
      ? parseInt(String(this.queryString.limit), 20) || 20
      : 20;
    const skip = (page - 1) * limit;

    this.query = this.query.skip(skip).limit(limit);
    return this;
  }

  public async exec(): Promise<{ data: unknown[]; total: number }> {
    const [data, total] = await Promise.all([
      this.query.lean().exec(),
      this.query.model.countDocuments(this.query.getFilter()),
    ]);
    return { data, total };
  }

  public populate(populateOptions: PopulateOptions | PopulateOptions[]): this {
    this.query = this.query.populate(populateOptions);
    return this;
  }
}
