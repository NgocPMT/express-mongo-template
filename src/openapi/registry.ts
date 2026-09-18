import { OpenAPIRegistry } from '@asteasolutions/zod-to-openapi';
import './zod.js';
import { registerAuthOpenApi } from '../modules/auth/auth.openapi.js';
import { registerHealthOpenApi } from '../modules/health/health.openapi.js';

export const registry = new OpenAPIRegistry();

registry.registerComponent('securitySchemes', 'bearerAuth', {
  type: 'http',
  scheme: 'bearer',
  bearerFormat: 'JWT',
});

registerHealthOpenApi(registry);
registerAuthOpenApi(registry);
