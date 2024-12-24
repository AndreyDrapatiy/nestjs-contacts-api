import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ versionKey: false, timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  toJSON() {
    const obj = this.toObject();
    delete obj.password;
    return obj;
  }
}

export const UserSchema = SchemaFactory.createForClass(User);
