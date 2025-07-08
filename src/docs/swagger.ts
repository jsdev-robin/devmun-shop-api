import swaggerAutogen from 'swagger-autogen';

const doc = {
  info: {
    title: 'My API',
    description: 'Description',
  },
  host: 'localhost:3000',
};

const outputFile = './swagger-output.json';
const routes = ['./src/routes/sellerAuthRoute.ts'];

/* NOTE: Ensure that the route file is the main entry for your routes,
   and you may need to pass only the root route file like app.ts or routes.ts */

swaggerAutogen(outputFile, routes, doc); // Generate Swagger documentation
