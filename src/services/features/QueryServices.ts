import { Document, Model, PopulateOptions, Query } from 'mongoose';
import QueryString from 'qs';

export class QueryServices<T extends Document> {
  private query: Query<T[], T>;
  private queryString: QueryString.ParsedQs;

  // Initialize with model and query params
  constructor(model: Model<T>, queryString: QueryString.ParsedQs) {
    this.query = model.find();
    this.queryString = queryString;
  }

  // Apply filters from query params
  public filter(): this {
    // Exclude pagination/sorting fields
    const queryObj = { ...this.queryString };
    const excludedFields = ['page', 'limit', 'sort', 'fields'];
    excludedFields.forEach((el) => delete queryObj[el]);

    // Convert operators (eq, gt, etc.) to MongoDB syntax ($eq, $gt)
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(
      /\b(eq|ne|gt|gte|lt|lte|in|nin|regex|exists|all|size|elemMatch|type|mod|not|and|or|nor|text|where|geoWithin|geoIntersects|near|nearSphere|expr|jsonSchema|bitsAllClear|bitsAllSet|bitsAnyClear|bitsAnySet|rand)\b/g,
      (match) => `$${match}`
    );

    // Treat string values as regex searches (case-insensitive)
    const parsedQuery = JSON.parse(queryStr);
    Object.entries(parsedQuery).forEach(([key, value]) => {
      if (typeof value === 'string') {
        parsedQuery[key] = { $regex: value, $options: 'i' };
      }
    });

    this.query = this.query.find(parsedQuery);
    return this;
  }

  // Search across multiple fields
  public globalSearch(fields: string[]): this {
    const search = this.queryString.q as string;
    if (search && fields.length > 0) {
      // Build OR conditions for each field
      const orConditions = fields.map((field) => ({
        [field]: { $regex: search, $options: 'i' },
      }));

      this.query = this.query.model.find();
      this.query = this.query.find({ $or: orConditions });
    }
    return this;
  }

  // Apply sorting (default: newest first)
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

  // Limit returned fields (default: exclude __v)
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

  // Paginate results (default: page=1, limit=20)
  public paginate(): this {
    const page = this.queryString.page
      ? parseInt(String(this.queryString.page), 10) || 1
      : 1;
    const limit = this.queryString.limit
      ? parseInt(String(this.queryString.limit), 10) || 20
      : 20;
    const skip = (page - 1) * limit;

    this.query = this.query.skip(skip).limit(limit);
    return this;
  }

  // Execute query and return data + total count
  public async exec(): Promise<{ data: unknown[]; total: number }> {
    const [data, total] = await Promise.all([
      this.query.lean().exec(),
      this.query.model.countDocuments(this.query.getFilter()),
    ]);
    return { data, total };
  }

  // Populate referenced fields
  public populate(populateOptions: PopulateOptions | PopulateOptions[]): this {
    this.query = this.query.populate(populateOptions);
    return this;
  }
}
