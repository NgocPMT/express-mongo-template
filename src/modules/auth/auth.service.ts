import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import { env } from '../../config/env.js';
import type { UserDoc } from '../../models/user.model.js';
import { HTTP_STATUS } from '../../shared/constants/http-status.js';
import { createHttpError } from '../../shared/errors/http-error.js';
import { AUTH_CONFIG, AUTH_MESSAGES } from './auth.constants.js';
import { authRepository, type AuthRepository } from './auth.repository.js';
import type {
  AuthResponse,
  AuthTokens,
  LoginRequest,
  RefreshTokenResponse,
  RegisterRequest,
  UserProfile,
} from './auth.schemas.js';

interface TokenPayload {
  sub: string;
  email: string;
  role: string;
}

type ValidExpiresIn = NonNullable<jwt.SignOptions['expiresIn']>;

export class AuthService {
  constructor(private readonly repository: AuthRepository = authRepository) {}

  private generateTokens(user: { _id: unknown; email: string; role: string }): AuthTokens {
    const payload: TokenPayload = {
      sub: String(user._id),
      email: user.email,
      role: user.role,
    };

    const accessToken = jwt.sign(payload, env.JWT_ACCESS_SECRET, {
      expiresIn: env.JWT_ACCESS_EXPIRES_IN as ValidExpiresIn,
    });

    const refreshToken = jwt.sign(payload, env.JWT_REFRESH_SECRET, {
      expiresIn: env.JWT_REFRESH_EXPIRES_IN as ValidExpiresIn,
    });

    return { accessToken, refreshToken };
  }

  private mapUserProfile(user: UserDoc): UserProfile {
    const raw = user.toObject();
    return {
      id: String(user._id),
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      phone: user.phone,
      avatar_url: user.avatar_url,
      createdAt: raw.createdAt ? new Date(raw.createdAt).toISOString() : undefined,
      updatedAt: raw.updatedAt ? new Date(raw.updatedAt).toISOString() : undefined,
    };
  }

  async register(input: RegisterRequest): Promise<AuthResponse> {
    const exists = await this.repository.existsByEmail(input.email);
    if (exists) {
      throw createHttpError(HTTP_STATUS.HTTP_409_CONFLICT, AUTH_MESSAGES.USER_ALREADY_EXISTS);
    }

    const password_hash = await bcrypt.hash(input.password, AUTH_CONFIG.BCRYPT_SALT_ROUNDS);

    const user = await this.repository.createUser({
      email: input.email,
      name: input.name,
      password_hash,
      ...(input.phone ? { phone: input.phone } : {}),
    });

    const tokens = this.generateTokens(user);
    return {
      user: this.mapUserProfile(user),
      tokens,
    };
  }

  async login(input: LoginRequest): Promise<AuthResponse> {
    const user = await this.repository.findByEmailWithPassword(input.email);
    if (!user) {
      throw createHttpError(HTTP_STATUS.HTTP_401_UNAUTHORIZED, AUTH_MESSAGES.INVALID_CREDENTIALS);
    }

    const isMatch = await bcrypt.compare(input.password, user.password_hash);
    if (!isMatch) {
      throw createHttpError(HTTP_STATUS.HTTP_401_UNAUTHORIZED, AUTH_MESSAGES.INVALID_CREDENTIALS);
    }

    if (user.status !== 'active') {
      throw createHttpError(HTTP_STATUS.HTTP_403_FORBIDDEN, AUTH_MESSAGES.ACCOUNT_INACTIVE);
    }

    const tokens = this.generateTokens(user);
    return {
      user: this.mapUserProfile(user),
      tokens,
    };
  }

  async refreshTokens(refreshToken: string): Promise<RefreshTokenResponse> {
    try {
      const decoded = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET) as unknown as TokenPayload;

      const user = await this.repository.findById(decoded.sub);
      if (!user || user.status !== 'active') {
        throw createHttpError(HTTP_STATUS.HTTP_401_UNAUTHORIZED, AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
      }

      return this.generateTokens(user);
    } catch {
      throw createHttpError(HTTP_STATUS.HTTP_401_UNAUTHORIZED, AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
    }
  }

  async getCurrentUser(userId: string): Promise<UserProfile> {
    const user = await this.repository.findById(userId);
    if (!user) {
      throw createHttpError(HTTP_STATUS.HTTP_404_NOT_FOUND, AUTH_MESSAGES.USER_NOT_FOUND);
    }

    return this.mapUserProfile(user);
  }
}

export const authService = new AuthService();
