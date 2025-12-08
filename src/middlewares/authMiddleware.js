import { ApiError } from '../exeptions/api.error.js';
import { jwtService } from '../services/jwt.service.js';

export const authMiddleware = function (req, res, next) {
  const autorization = req.headers['autorization'] || '';

  const [, token] = autorization.split(' ');

  if (!autorization || !token) {
    throw ApiError.unauthorized();
  }

  const userData = jwtService.verify(token);

  if (!userData) {
    throw ApiError.unauthorized();
  }

  next();
};
