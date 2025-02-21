import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from '../schemas/user.schema';
import { Model, Types } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async findOne(email: string): Promise<User | null> {
    return this.userModel.findOne({ email }).exec();
  }

  async findOneById(userId: string): Promise<User | null> {
    return this.userModel.findOne({ _id: userId }).exec();
  }

  async create(name: string, email: string, password: string): Promise<User> {
    const createdUser = new this.userModel({
      name,
      email,
      password,
    });

    return createdUser.save();
  }

  async updateRefreshToken(userId: Types.ObjectId, refreshToken: string) {
    const hashedToken = await bcrypt.hash(refreshToken, 10);

    await this.userModel.findByIdAndUpdate(userId, { refreshToken: hashedToken });
  }
}
