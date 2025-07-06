import ejs from 'ejs';
import nodemailer from 'nodemailer';
import path from 'path';
import config from '../../configs/config';

interface IEmailData {
  user: {
    email: string;
  };
}

export class SendMail {
  private readonly data: IEmailData;

  constructor(data: IEmailData) {
    this.data = data;
  }

  private transporter = nodemailer.createTransport({
    host: config.EMAIL_HOST,
    port: Number(config.EMAIL_PORT),
    secure: true,
    auth: {
      user: config.EMAIL_USERNAME,
      pass: config.EMAIL_PASSWORD,
    },
  });

  send = async (template: string, subject: string) => {
    try {
      await this.transporter.sendMail({
        from: `Jsdev Robin <${config.EMAIL_FROM}>`,
        to: this.data.user.email,
        subject: subject,
        html: await ejs.renderFile(
          path.join(__dirname, `../../views/emails/${template}.ejs`),
          {
            data: { ...this.data },
            subject,
          }
        ),
      });
    } catch (error) {
      console.error(`Error sending email:`, error);
    }
  };

  public async verifyEmail(): Promise<void> {
    await this.send('verifyEmail', 'Email verify');
  }

  public async emailChangeRequest(): Promise<void> {
    await this.send('emailChangeRequest', 'Email Address Change Notification');
  }

  public async emailChangeAlert(): Promise<void> {
    await this.send('emailChangeAlert', 'Email Change Alert');
  }
}
