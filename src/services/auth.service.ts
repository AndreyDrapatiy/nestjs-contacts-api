import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from '../dtos/create-user.dto';
import { LoginUserDto } from '../dtos/login-user.dto';
import { User } from '../schemas/user.schema';
import { Session } from '../schemas/session.schema';
import { randomBytes } from 'crypto';
import { FIFTEEN_MINUTES, SMTP, TEMPLATES_DIR, THIRTY_DAYS } from '../constans';
import env from '../utils/env';
import * as jwt from 'jsonwebtoken';
import { sendEmail } from '../utils/sendMail';
import handlebars from 'handlebars';
import * as path from 'path';
import * as fs from 'node:fs/promises';
import { ResetPasswordDto } from '../dtos/reset-password.dto';
import { UsersService } from './users.service';
import { JwtService } from '@nestjs/jwt';
import { IsEmail, IsString } from 'class-validator';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Session.name) private sessionModel: Model<Session>,
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

  async login(user: User): Promise<{ accessToken: string, refreshToken: string }> {
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user._id };

    const accessToken = this.jwtService.sign(payload, {
      secret: env('JWT_SECRET'),
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: env('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
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
        expiresIn: '15m',
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

  async logout(sessionId: string): Promise<void> {
    await this.sessionModel.deleteOne({ _id: sessionId });
  }

  async requestResetPassword(email: string): Promise<void> {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const resetToken = jwt.sign(
      {
        sub: user._id,
        email,
      },
      env('JWT_SECRET'),
      {
        expiresIn: '15m',
      },
    );

    const resetPasswordTemplatePath = path.join(
      TEMPLATES_DIR,
      'reset-password-email.html',
    );

    const templateSource = (
      await fs.readFile(resetPasswordTemplatePath)
    ).toString();

    const template = handlebars.compile(templateSource);

    const html = template({
      name: user.name,
      link: `${env('APP_DOMAIN')}/reset-password?token=${resetToken}`,
    });

    try {
      await sendEmail({
        from: env(SMTP.SMTP_FROM),
        to: email,
        subject: 'Reset your password',
        html,
      });
    } catch (error) {
      throw new HttpException(
        'Failed to send email, please try again later.',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async resetPassword(resetPassword: ResetPasswordDto): Promise<void> {
    const { token } = resetPassword;

    interface JwtPayload {
      email: string;
      sub: string;
    }

    let entries: JwtPayload;

    try {
      entries = jwt.verify(token, env('JWT_SECRET')) as JwtPayload;
    } catch (err) {
      if (err instanceof Error)
        throw new HttpException(
          'Token is expired or invalid.',
          HttpStatus.UNAUTHORIZED,
        );
      throw err;
    }

    const user = await this.userModel.findOne({
      email: entries.email,
      _id: entries.sub,
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const encryptedPassword = await bcrypt.hash(resetPassword.password, 10);

    await this.userModel.updateOne(
      { _id: user._id },
      { password: encryptedPassword },
    );
    await this.sessionModel.deleteOne({ userId: user._id });
  }
}
