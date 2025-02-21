import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ versionKey: false, timestamps: true })
export class Contact extends Document {
  @Prop({ required: true })
  userId: string;

  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  phoneNumber: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ default: false })
  isFavourite: boolean;

  @Prop({ required: true, enum: ['personal', 'business', 'home'] })
  contactType: string;
}

export const ContactSchema = SchemaFactory.createForClass(Contact);
