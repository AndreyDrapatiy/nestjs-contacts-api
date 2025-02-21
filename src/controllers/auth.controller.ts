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
import { AuthService } from '../services/auth.service';
import { CreateUserDto } from '../dtos/create-user.dto';
import { User } from '../schemas/user.schema';
import {  Response, Request as ExpressRequest } from 'express';
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
      sameSite: 'lax',
      path: '/auth/refresh',
    });

    return res.json({ accessToken });
  }

  @Post('logout')
  async logout(@Request() req: ExpressRequest, @Res() res: Response) {
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: env('NODE_ENV') === 'production',
      sameSite: 'lax',
      path: '/auth/refresh',
    });

    return res.json({ message: 'Logged out successfully' });
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
