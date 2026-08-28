import { Resend } from "resend";
import {
  signupEmailTemplate,
  passwordResetNotificationEmailTemplate,
  passwordResetTokenEmailTemplate,
  twoFactorCodeEmailTemplate,
  twoFactorEnabledEmailTemplate,
  accountDeactivatedEmailTemplate,
  accountReactivatedEmailTemplate,
  accountActivateEmailcodeTemplate,
  accountDeactivatedEmailcodeTemplate,
} from "../../models/emailTemplates.js";

const resend = new Resend(process.env.RESEND_API_KEY);
export const sendsignupEmailTemplate = async (email, token) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Welcom To Our Backend Services",
    html: signupEmailTemplate(token),
  });
};

export const sendpasswordResetTokenEmailTemplate = async (email, code) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Use this code to reset your password",
    html: passwordResetTokenEmailTemplate(code),
  });
};

export const sendpasswordResetNotificationEmailTemplate = async (email) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Your password was changed",
    html: passwordResetNotificationEmailTemplate(),
  });
};

export const sendtwoFactorEnabledEmailTemplate = async (email) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Two-Factor Authentication Enabled",
    html: twoFactorEnabledEmailTemplate(),
  });
};
export const sendaccountactivatenotification = async (email) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Your account is activated!",
    html: accountReactivatedEmailTemplate(),
  });
};
export const sendaccountdeactivatenotification = async (email) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Your account is Deactivated!",
    html: accountDeactivatedEmailTemplate(),
  });
};

export const sendtwoFactorCodeEmailTemplate = async (email, code) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Enable Two-factor Authentication",
    html: twoFactorCodeEmailTemplate(code),
  });
};

export const sendaccountdeactivateCodeemail = async (email, code) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Deactivate Your account!",
    html: accountDeactivatedEmailcodeTemplate(code),
  });
};
export const sendaccountactivateCodeemail = async (email, code) => {
  await resend.emails.send({
    from: "Backend <onboarding@resend.dev>",
    to: email,
    subject: "Activate Your Account!",
    html: accountActivateEmailcodeTemplate(code),
  });
};
