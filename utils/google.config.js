import { google } from "googleapis";

export const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT,
  process.env.GOOGLE_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);
