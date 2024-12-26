import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { CreateUserDto } from '../dtos/create-user.dto';
import { User } from '../schemas/user.schema';
import { LoginUserDto } from '../dtos/login-user.dto';
import { THIRTY_DAYS } from '../constans';
import { Request, Response } from 'express';
import { RequestResetPasswordDto } from '../dtos/request-reset-password.dto';
import { ResetPasswordDto } from '../dtos/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUser: CreateUserDto): Promise<User> {
    return await this.authService.register(createUser);
  }

  @Post('login')
  async login(
    @Body() loginUser: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const session = await this.authService.login(loginUser);

    res.cookie('refreshToken', session.refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + THIRTY_DAYS),
    });

    res.cookie('sessionId', session.sessionId, {
      httpOnly: true,
      expires: new Date(Date.now() + THIRTY_DAYS),
    });

    return { accessToken: session.accessToken };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    if (req.cookies.sessionId) {
      await this.authService.logout(req.cookies.sessionId);
    }

    res.clearCookie('sessionId');
    res.clearCookie('refreshToken');
  }

  @Post('request-reset-password')
  async requestResetPassword(
    @Body() requestResetPassword: RequestResetPasswordDto,
    @Res() res: Response,
  ) {
    await this.authService.requestResetPassword(requestResetPassword.email);

    res
      .status(HttpStatus.OK)
      .json({ message: 'Reset password email sent successfully.' });
  }

  @Post('reset-password')
  async resetPassword(
    @Body() resetPassword: ResetPasswordDto,
    @Res() res: Response,
  ) {
    await this.authService.resetPassword(resetPassword);

    res
      .status(HttpStatus.OK)
      .json({ message: 'Password was successfully reset!' });
  }
}
