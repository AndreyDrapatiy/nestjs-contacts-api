import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { ContactController } from '../controllers/contact.controller';
import { ContactService } from '../services/contact.service';
import { AuthModule } from './auth.module';
import { Contact, ContactSchema } from '../schemas/contact.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Contact.name, schema: ContactSchema }]),
    AuthModule,
  ],
  controllers: [ContactController],
  providers: [ContactService],
})
export class ContactModule {}
