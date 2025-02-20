import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from '../controllers/auth.controller';
import { AuthService } from '../services/auth.service';
import { User, UserSchema } from '../schemas/user.schema';
import { Session, SessionSchema } from '../schemas/session.schema';
import { UsersService } from '../services/users.service';
import { UsersModule } from './users.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from '../strategies/auth/local.strategy';
import { JwtModule, JwtService } from '@nestjs/jwt';
import env from '../utils/env';
import { JwtStrategy } from '../strategies/auth/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: env('JWT_SECRET'),
      signOptions: { expiresIn: '60s' },
    }),
    MongooseModule.forFeature([
      { name: Session.name, schema: SessionSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, UsersService, LocalStrategy, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
