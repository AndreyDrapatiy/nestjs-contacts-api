import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
  Request, HttpException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { CreateUserDto } from '../dtos/create-user.dto';
import { User } from '../schemas/user.schema';
import { LoginUserDto } from '../dtos/login-user.dto';
import { THIRTY_DAYS } from '../constans';
import {  Response, Request as ExpressRequest } from 'express';
import { RequestResetPasswordDto } from '../dtos/request-reset-password.dto';
import { ResetPasswordDto } from '../dtos/reset-password.dto';
import {LocalAuthGuard} from '../guards/auth/local-auth.guard'
import env from '../utils/env';
import { JwtRefreshGuard } from '../guards/auth/jwt.refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req: ExpressRequest, @Res() res: Response) {
    const { accessToken, refreshToken } = await this.authService.login(req.user as User);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: env('NODE_ENV') === 'production',
      sameSite: 'strict',
      path: '/auth/refresh',
    });

    return res.json({ accessToken });
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUser: CreateUserDto): Promise<User> {
    return await this.authService.register(createUser);
  }

  @Post('refresh')
  @UseGuards(JwtRefreshGuard)
  async refreshToken(@Request() req: ExpressRequest) {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      throw new HttpException('Refresh token is missing', HttpStatus.BAD_REQUEST);
    }
    return await this.authService.refreshToken(refreshToken);
  }
}
