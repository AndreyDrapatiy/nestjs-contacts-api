import { NestFactory } from '@nestjs/core';
import { AppModule } from './modules/app.module';
import * as cookieParser from 'cookie-parser';
import * as cors from 'cors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(
    cors({
      origin: (origin, callback) => {
        const allowedOrigins = ['http://localhost:3000', 'http://example.com'];
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true,
    }),
  );
  app.use(cookieParser());
  await app.listen(process.env.PORT ?? 8080);
}
bootstrap();
