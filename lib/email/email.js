import { Resend } from "resend";
import {
  signupEmailTemplate,
  passwordResetNotificationEmailTemplate,
  passwordResetTokenEmailTemplate,
  twoFactorCodeEmailTemplate,
  twoFactorSignInEmailTemplate,
  twoFactorEnabledEmailTemplate,
  accountDeactivatedEmailTemplate,
  accountReactivatedEmailTemplate,
  accountActivateEmailcodeTemplate,
  accountDeactivatedEmailcodeTemplate,
} from "../../utils/emailTemplates.js";

const resend = new Resend(process.env.RESEND_API_KEY);
const appName = process.env.APP_NAME || "Backend Services";
const sender = process.env.EMAIL_FROM || `${appName} <onboarding@resend.dev>`;

const sendEmail = async ({ email, subject, html }) =>
  resend.emails.send({ from: sender, to: email, subject, html });

export const sendsignupEmailTemplate = (email, token) =>
  sendEmail({
    email,
    subject: `Welcome to ${appName}`,
    html: signupEmailTemplate(token),
  });

export const sendpasswordResetTokenEmailTemplate = (email, token) =>
  sendEmail({
    email,
    subject: `Reset your ${appName} password`,
    html: passwordResetTokenEmailTemplate(token),
  });

export const sendpasswordResetNotificationEmailTemplate = (email) =>
  sendEmail({
    email,
    subject: `Your ${appName} password was changed`,
    html: passwordResetNotificationEmailTemplate(),
  });

export const sendtwoFactorEnabledEmailTemplate = (email) =>
  sendEmail({
    email,
    subject: "Two-factor authentication enabled",
    html: twoFactorEnabledEmailTemplate(),
  });

export const sendaccountactivatenotification = (email) =>
  sendEmail({
    email,
    subject: "Your account is active",
    html: accountReactivatedEmailTemplate(),
  });

export const sendaccountdeactivatenotification = (email) =>
  sendEmail({
    email,
    subject: "Your account is deactivated",
    html: accountDeactivatedEmailTemplate(),
  });

export const sendtwoFactorCodeEmailTemplate = (email, code) =>
  sendEmail({
    email,
    subject: "Confirm your two-factor authentication change",
    html: twoFactorCodeEmailTemplate(code),
  });

export const sendtwoFactorSignInEmailTemplate = (email, code) =>
  sendEmail({
    email,
    subject: `Your ${appName} sign-in code`,
    html: twoFactorSignInEmailTemplate(code),
  });

export const sendaccountdeactivateCodeemail = (email, code) =>
  sendEmail({
    email,
    subject: "Confirm account deactivation",
    html: accountDeactivatedEmailcodeTemplate(code),
  });

export const sendaccountactivateCodeemail = (email, code) =>
  sendEmail({
    email,
    subject: "Confirm account reactivation",
    html: accountActivateEmailcodeTemplate(code),
  });
