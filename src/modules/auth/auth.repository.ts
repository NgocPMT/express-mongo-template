import { Account } from '../../models/account.model.js';
import { User, type UserDoc } from '../../models/user.model.js';

export interface CreateUserWithAccountData {
  email: string;
  username: string;
  password_hash: string;
}

export interface UserWithPassword {
  user: UserDoc;
  password_hash: string;
}

export class AuthRepository {
  async findByIdentifierWithPassword(identifier: string): Promise<UserWithPassword | null> {
    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    }).exec();

    if (!user) {
      return null;
    }

    const account = await Account.findOne({
      user_id: user._id,
      provider: 'local',
    })
      .select('+password_hash')
      .exec();

    if (!account?.password_hash) {
      return null;
    }

    return {
      user,
      password_hash: account.password_hash,
    };
  }

  async findById(id: string): Promise<UserDoc | null> {
    return User.findById(id).exec();
  }

  async existsByEmail(email: string): Promise<boolean> {
    const count = await User.countDocuments({ email }).exec();
    return count > 0;
  }

  async existsByUsername(username: string): Promise<boolean> {
    const count = await User.countDocuments({ username }).exec();
    return count > 0;
  }

  async createUserWithAccount(data: CreateUserWithAccountData): Promise<UserDoc> {
    const user = new User({
      email: data.email,
      username: data.username,
    });
    await user.save();

    const account = new Account({
      user_id: user._id,
      provider: 'local',
      password_hash: data.password_hash,
    });
    await account.save();

    return user;
  }
}

export const authRepository = new AuthRepository();
