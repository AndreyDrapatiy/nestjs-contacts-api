import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from '../controllers/app.controller';
import { AppService } from '../services/app.service';
import env from '../utils/env';
import { AuthModule } from './auth.module';
import { ContactModule } from './contact.module';

const user = env('MONGODB_USER');
const pwd = env('MONGODB_PASSWORD');
const url = env('MONGODB_URL');
const db = env('MONGODB_DB');

const mongoStr = `mongodb+srv://${user}:${pwd}@${url}/${db}?retryWrites=true&w=majority`;

@Module({
  imports: [
    MongooseModule.forRoot(mongoStr || 'mongodb://localhost:27017'),
    AuthModule,
    ContactModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
