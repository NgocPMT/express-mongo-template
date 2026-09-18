import { describe, expect, it, vi, beforeEach } from 'vitest';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../../../src/modules/auth/auth.service.js';
import type { AuthRepository } from '../../../src/modules/auth/auth.repository.js';
import { env } from '../../../src/config/env.js';

describe('AuthService', () => {
  let mockRepo: Partial<AuthRepository>;
  let authService: AuthService;

  beforeEach(() => {
    mockRepo = {
      existsByEmail: vi.fn(),
      createUser: vi.fn(),
      findByEmailWithPassword: vi.fn(),
      findById: vi.fn(),
    };
    authService = new AuthService(mockRepo as AuthRepository);
  });

  describe('register', () => {
    it('creates a user and returns auth tokens', async () => {
      mockRepo.existsByEmail = vi.fn().mockResolvedValue(false);
      mockRepo.createUser = vi.fn().mockResolvedValue({
        _id: 'user-id-1',
        email: 'test@example.com',
        name: 'Test User',
        role: 'user',
        status: 'active',
        toObject: () => ({
          _id: 'user-id-1',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          status: 'active',
        }),
      });

      const result = await authService.register({
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.tokens.accessToken).toBeDefined();
      expect(result.tokens.refreshToken).toBeDefined();
    });

    it('throws 409 when user with email already exists', async () => {
      mockRepo.existsByEmail = vi.fn().mockResolvedValue(true);

      await expect(
        authService.register({
          email: 'existing@example.com',
          password: 'password123',
          name: 'Existing User',
        }),
      ).rejects.toThrow();
    });
  });

  describe('login', () => {
    it('authenticates user and returns tokens', async () => {
      const passwordHash = await bcrypt.hash('password123', 10);
      mockRepo.findByEmailWithPassword = vi.fn().mockResolvedValue({
        _id: 'user-id-1',
        email: 'test@example.com',
        name: 'Test User',
        password_hash: passwordHash,
        role: 'user',
        status: 'active',
        toObject: () => ({
          _id: 'user-id-1',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user',
          status: 'active',
        }),
      });

      const result = await authService.login({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.tokens.accessToken).toBeDefined();
    });

    it('throws 401 when password does not match', async () => {
      const passwordHash = await bcrypt.hash('different-password', 10);
      mockRepo.findByEmailWithPassword = vi.fn().mockResolvedValue({
        _id: 'user-id-1',
        email: 'test@example.com',
        password_hash: passwordHash,
        status: 'active',
      });

      await expect(
        authService.login({
          email: 'test@example.com',
          password: 'wrong-password',
        }),
      ).rejects.toThrow();
    });
  });

  describe('refreshTokens', () => {
    it('returns new tokens for a valid refresh token', async () => {
      const refreshToken = jwt.sign(
        { sub: 'user-id-1', email: 'test@example.com', role: 'user' },
        env.JWT_REFRESH_SECRET,
      );

      mockRepo.findById = vi.fn().mockResolvedValue({
        _id: 'user-id-1',
        email: 'test@example.com',
        role: 'user',
        status: 'active',
      });

      const tokens = await authService.refreshTokens(refreshToken);

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
    });
  });
});
