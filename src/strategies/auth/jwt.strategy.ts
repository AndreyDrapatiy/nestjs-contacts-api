import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import env from '../../utils/env';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: env('JWT_SECRET'),
      ignoreExpiration: false,
    });
  }

  async validate(payload: any) {

    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token');
    }

    return { _id: payload.sub, email: payload.email };
  }
}
