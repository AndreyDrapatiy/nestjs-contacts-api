import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Contact } from '../schemas/contact.schema';

@Injectable()
export class ContactService {
  constructor(@InjectModel(Contact.name) private readonly contactModel: Model<Contact>) {}

  async getContacts(userId: Types.ObjectId): Promise<Contact[]> {
    return this.contactModel.find({ userId }).exec();
  }
}

