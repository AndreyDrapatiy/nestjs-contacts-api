import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from '../controllers/auth.controller';
import { AuthService } from '../services/auth.service';
import { User, UserSchema } from '../schemas/user.schema';
import { Session, SessionSchema } from '../schemas/session.schema';

@Module({
  imports: [MongooseModule.forFeature([
    { name: Session.name, schema: SessionSchema },
    { name: User.name, schema: UserSchema }
  ])],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
