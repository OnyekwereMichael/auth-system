import dotenv from "dotenv";
import {MailtrapClient} from "mailtrap";
dotenv.config();

const TOKEN = process.env.MAILTRAP_API_TOKEN;

export const mailtrapClient = new MailtrapClient({
  token: TOKEN,
});

export const sender = {
  email: "hello@demomailtrap.co",
  name: "Michael",
};
