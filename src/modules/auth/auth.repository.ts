import { User, type UserDoc } from '../../models/user.model.js';

export interface CreateUserData {
  email: string;
  name: string;
  password_hash: string;
  phone?: string;
}

export class AuthRepository {
  async findByEmailWithPassword(email: string): Promise<(UserDoc & { password_hash: string }) | null> {
    return User.findOne({ email }).select('+password_hash').exec() as Promise<(UserDoc & { password_hash: string }) | null>;
  }

  async findById(id: string): Promise<UserDoc | null> {
    return User.findById(id).exec();
  }

  async existsByEmail(email: string): Promise<boolean> {
    const count = await User.countDocuments({ email }).exec();
    return count > 0;
  }

  async createUser(data: CreateUserData): Promise<UserDoc> {
    const doc = new User({
      email: data.email,
      name: data.name,
      password_hash: data.password_hash,
      ...(data.phone ? { phone: data.phone } : {}),
    });
    return doc.save();
  }
}

export const authRepository = new AuthRepository();
