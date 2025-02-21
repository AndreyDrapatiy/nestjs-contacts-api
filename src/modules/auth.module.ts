import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from '../controllers/auth.controller';
import { AuthService } from '../services/auth.service';
import { User, UserSchema } from '../schemas/user.schema';
import { UserService } from '../services/user.service';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from '../strategies/auth/local.strategy';
import { JwtModule } from '@nestjs/jwt';
import env from '../utils/env';
import { JwtStrategy } from '../strategies/auth/jwt.strategy';
import { JwtRefreshStrategy } from '../strategies/auth/jwt.refresh.strategy';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: env('JWT_SECRET'),
      signOptions: { expiresIn: '60s' },
    }),
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, UserService, LocalStrategy, JwtStrategy, JwtRefreshStrategy],
  exports: [AuthService],
})
export class AuthModule {}
