import { SendMailOptions, createTransport } from 'nodemailer';

import { SMTP } from '../constans';
import env from './env';

const transporter = createTransport({
  host: env(SMTP.SMTP_HOST),
  port: Number(env(SMTP.SMTP_PORT)),
  auth: {
    user: env(SMTP.SMTP_USER),
    pass: env(SMTP.SMTP_PASSWORD),
  },
});

export const sendEmail = async (options: SendMailOptions): Promise<void> => {
  await transporter.sendMail(options);
};
