import { AuthSchema } from './AuthSchema';

export const authModel = new AuthSchema().getSchema();
