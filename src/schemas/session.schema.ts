import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ versionKey: false, timestamps: false })
export class Session extends Document {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  accessToken: string;

  @Prop({ required: true })
  refreshToken: string;

  @Prop({ required: true })
  accessTokenValidUntil: Date;

  @Prop({ required: true })
  refreshTokenValidUntil: Date;

  // Optionally, ensure that _id is typed correctly as ObjectId
  _id: string;  // This is just to ensure the type is inferred correctly for _id.
}

export const SessionSchema = SchemaFactory.createForClass(Session);
