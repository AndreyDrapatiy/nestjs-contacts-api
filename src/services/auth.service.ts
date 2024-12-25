import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { LoginUserDto } from '../dtos/login-user.dto';
import { User } from '../schemas/user.schema';
import { Session } from '../schemas/session.schema';
import { randomBytes } from 'crypto';
import { FIFTEEN_MINUTES, THIRTY_DAYS } from '../constans';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Session.name) private sessionModel: Model<Session>
  ) {}

  async register(createUserDto: CreateUserDto): Promise<User> {
    const { email, password, name } = createUserDto;

    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new HttpException('Email already in use', HttpStatus.CONFLICT);
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    const createdUser = new this.userModel({
      name,
      email,
      password: encryptedPassword,
    });

    return createdUser.save();
  }

  async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string; refreshToken: string; sessionId: string;}> {
    const { email, password } = loginUserDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new HttpException('Email or password is incorrect', HttpStatus.UNAUTHORIZED);
    }

    await this.sessionModel.deleteOne({ userId: user._id });

    const accessToken = randomBytes(30).toString('base64');
    const refreshToken = randomBytes(30).toString('base64');

    const session = await this.sessionModel.create({
      userId: user._id,
      accessToken,
      refreshToken,
      accessTokenValidUntil: new Date(Date.now() + FIFTEEN_MINUTES),
      refreshTokenValidUntil: new Date(Date.now() + THIRTY_DAYS),
    });

    return {
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      sessionId: session._id.toString(),
    };
  }

  async logout(sessionId: string): Promise<void> {
    await this.sessionModel.deleteOne({ _id: sessionId });
  }
}
