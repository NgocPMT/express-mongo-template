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
      existsByUsername: vi.fn(),
      createUserWithAccount: vi.fn(),
      findByIdentifierWithPassword: vi.fn(),
      findById: vi.fn(),
    };
    authService = new AuthService(mockRepo as AuthRepository);
  });

  describe('register', () => {
    it('creates a user and returns auth tokens', async () => {
      mockRepo.existsByEmail = vi.fn().mockResolvedValue(false);
      mockRepo.existsByUsername = vi.fn().mockResolvedValue(false);
      mockRepo.createUserWithAccount = vi.fn().mockResolvedValue({
        _id: 'user-id-1',
        email: 'test@example.com',
        username: 'testuser',
        role: 'user',
        status: 'active',
        toObject: () => ({
          _id: 'user-id-1',
          email: 'test@example.com',
          username: 'testuser',
          role: 'user',
          status: 'active',
        }),
      });

      const result = await authService.register({
        email: 'test@example.com',
        password: 'password123',
        username: 'testuser',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.user.username).toBe('testuser');
      expect(result.tokens.accessToken).toBeDefined();
      expect(result.tokens.refreshToken).toBeDefined();
    });

    it('throws 409 when user with email already exists', async () => {
      mockRepo.existsByEmail = vi.fn().mockResolvedValue(true);

      await expect(
        authService.register({
          email: 'existing@example.com',
          password: 'password123',
          username: 'testuser',
        }),
      ).rejects.toThrow();
    });

    it('throws 409 when user with username already exists', async () => {
      mockRepo.existsByEmail = vi.fn().mockResolvedValue(false);
      mockRepo.existsByUsername = vi.fn().mockResolvedValue(true);

      await expect(
        authService.register({
          email: 'new@example.com',
          password: 'password123',
          username: 'existinguser',
        }),
      ).rejects.toThrow();
    });
  });

  describe('login', () => {
    it('authenticates user with email identifier and returns tokens', async () => {
      const passwordHash = await bcrypt.hash('password123', 10);
      mockRepo.findByIdentifierWithPassword = vi.fn().mockResolvedValue({
        user: {
          _id: 'user-id-1',
          email: 'test@example.com',
          username: 'testuser',
          role: 'user',
          status: 'active',
          toObject: () => ({
            _id: 'user-id-1',
            email: 'test@example.com',
            username: 'testuser',
            role: 'user',
            status: 'active',
          }),
        },
        password_hash: passwordHash,
      });

      const result = await authService.login({
        identifier: 'test@example.com',
        password: 'password123',
      });

      expect(result.user.email).toBe('test@example.com');
      expect(result.user.username).toBe('testuser');
      expect(result.tokens.accessToken).toBeDefined();
    });

    it('authenticates user with username identifier and returns tokens', async () => {
      const passwordHash = await bcrypt.hash('password123', 10);
      mockRepo.findByIdentifierWithPassword = vi.fn().mockResolvedValue({
        user: {
          _id: 'user-id-1',
          email: 'test@example.com',
          username: 'testuser',
          role: 'user',
          status: 'active',
          toObject: () => ({
            _id: 'user-id-1',
            email: 'test@example.com',
            username: 'testuser',
            role: 'user',
            status: 'active',
          }),
        },
        password_hash: passwordHash,
      });

      const result = await authService.login({
        identifier: 'testuser',
        password: 'password123',
      });

      expect(result.user.username).toBe('testuser');
      expect(result.tokens.accessToken).toBeDefined();
    });

    it('throws 401 when password does not match', async () => {
      const passwordHash = await bcrypt.hash('different-password', 10);
      mockRepo.findByIdentifierWithPassword = vi.fn().mockResolvedValue({
        user: {
          _id: 'user-id-1',
          email: 'test@example.com',
          username: 'testuser',
          role: 'user',
          status: 'active',
          toObject: () => ({
            _id: 'user-id-1',
            email: 'test@example.com',
            username: 'testuser',
            role: 'user',
            status: 'active',
          }),
        },
        password_hash: passwordHash,
      });

      await expect(
        authService.login({
          identifier: 'test@example.com',
          password: 'wrong-password',
        }),
      ).rejects.toThrow();
    });

    it('throws 401 when identifier not found', async () => {
      mockRepo.findByIdentifierWithPassword = vi.fn().mockResolvedValue(null);

      await expect(
        authService.login({
          identifier: 'unknown@example.com',
          password: 'password123',
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
        username: 'testuser',
        role: 'user',
        status: 'active',
      });

      const tokens = await authService.refreshTokens(refreshToken);

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
    });
  });
});
