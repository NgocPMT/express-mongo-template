import type { Types } from 'mongoose';
import { Schema, model } from 'mongoose';

export const userRoles = ['user', 'admin'] as const;
export type UserRole = (typeof userRoles)[number];

export const userStatuses = ['active', 'inactive', 'suspended'] as const;
export type UserStatus = (typeof userStatuses)[number];

export interface UserData {
  email: string;
  name: string;
  password_hash: string;
  role?: UserRole;
  status?: UserStatus;
  phone?: string;
  avatar_url?: string | null;
}

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    password_hash: {
      type: String,
      required: true,
      select: false,
    },
    role: {
      type: String,
      enum: userRoles,
      default: 'user',
      index: true,
    },
    status: {
      type: String,
      enum: userStatuses,
      default: 'active',
      index: true,
    },
    phone: {
      type: String,
      trim: true,
    },
    avatar_url: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: 'users',
  },
);

export const User = model('User', userSchema);
export type UserDoc = ReturnType<typeof User.prototype.toObject> & {
  _id: Types.ObjectId;
};
