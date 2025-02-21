import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { User } from '../schemas/user.schema';
import env from '../utils/env';
import { UserService } from './user.service';
import { JwtService } from '@nestjs/jwt';
import { IsEmail, IsString } from 'class-validator';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UserService,
    private jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
  ) {}

  async validateUser(email: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(email);

    if (!user) {
      return null;
    }

    const isMatch = await bcrypt.compare(pass, user.password);

    if (!isMatch) {
      return null;
    }

    const { password, ...result } = user.toObject();
    return result;
  }

  async login(user: User): Promise<{ accessToken: string; refreshToken: string }> {
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user._id };

    const accessToken = this.jwtService.sign(payload, {
      secret: env('JWT_SECRET'),
      expiresIn: '1m', // Adjust expiry as needed
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: env('JWT_REFRESH_SECRET'),
      expiresIn: '7d', // Adjust expiry as needed
    });

    await this.usersService.updateRefreshToken(user._id, refreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async register(createUserDto: CreateUserDto): Promise<User> {
    const { email, password, name } = createUserDto;

    const existingUser = await this.usersService.findOne(email);
    if (existingUser) {
      throw new HttpException('Email already in use', HttpStatus.CONFLICT);
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    return this.usersService.create(name, email, encryptedPassword);
  }

  async refreshToken(refreshToken: string): Promise<{ accessToken: string, refreshToken: string }> {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      const user = await this.usersService.findOne(payload.email)

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const newAccessToken = this.jwtService.sign({ email: user.email, sub: user._id }, {
        secret: process.env.JWT_SECRET,
        expiresIn: '1m',
      });

      const newRefreshToken = this.jwtService.sign({ email: user.email, sub: user._id }, {
        secret: process.env.JWT_REFRESH_SECRET,
        expiresIn: '7d',
      });

      await this.usersService.updateRefreshToken(user._id, newRefreshToken);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
