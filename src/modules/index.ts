import { Router, type Express } from 'express';
import { authRouter } from './auth/index.js';
import { healthRouter } from './health/index.js';

export function registerRoutes(app: Express): void {
  const apiV1Router = Router();
  apiV1Router.use('/auth', authRouter);

  app.use(healthRouter);
  app.use('/api/v1', apiV1Router);
}
