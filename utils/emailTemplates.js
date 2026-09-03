const appName = process.env.APP_NAME || "Backend Services";
const companyName = process.env.COMPANY_NAME || appName;
const supportEmail = process.env.SUPPORT_EMAIL || "support@example.com";

const escapeHtml = (value) =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

const getPasswordResetUrl = (token) => {
  const baseUrl = process.env.FRONTEND_URL || "http://localhost:3000";
  const resetUrl = new URL("/reset-password", baseUrl);
  resetUrl.searchParams.set("token", token);
  return resetUrl.toString();
};

const emailLayout = ({ eyebrow, title, body, code, action, notice }) => `
<!doctype html>
<html lang="en">
  <body style="margin:0;padding:32px 16px;background:#f4f7fb;color:#1f2937;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
        <tr><td style="padding:24px 36px;background:#111827;color:#ffffff;font-size:20px;font-weight:700;">${escapeHtml(appName)}</td></tr>
        <tr><td style="padding:36px;">
          <p style="margin:0 0 10px;color:#4f46e5;font-size:12px;font-weight:700;letter-spacing:1.4px;">${escapeHtml(eyebrow)}</p>
          <h1 style="margin:0 0 16px;color:#111827;font-size:28px;line-height:1.25;">${escapeHtml(title)}</h1>
          <div style="color:#4b5563;font-size:16px;line-height:1.6;">${body}</div>
          ${code ? `<div style="margin:28px 0;padding:18px;border:1px solid #c7d2fe;border-radius:10px;background:#eef2ff;color:#312e81;font-family:monospace;font-size:26px;font-weight:700;letter-spacing:6px;text-align:center;word-break:break-all;">${escapeHtml(code)}</div>` : ""}
          ${action ? `<table role="presentation" cellspacing="0" cellpadding="0" style="margin:28px 0;"><tr><td style="border-radius:8px;background:#4f46e5;"><a href="${escapeHtml(action.url)}" target="_blank" rel="noopener noreferrer" style="display:inline-block;padding:14px 22px;color:#ffffff;font-size:16px;font-weight:700;text-decoration:none;">${escapeHtml(action.label)}</a></td></tr></table>` : ""}
          ${notice ? `<p style="margin:28px 0 0;padding:14px 16px;border-left:3px solid #818cf8;background:#f9fafb;color:#4b5563;font-size:14px;line-height:1.5;">${notice}</p>` : ""}
        </td></tr>
        <tr><td style="padding:20px 36px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px;line-height:1.5;">&copy; ${new Date().getFullYear()} ${escapeHtml(companyName)}. Need help? Contact <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.</td></tr>
      </table>
    </td></tr></table>
  </body>
</html>`;

export const signupEmailTemplate = (code) =>
  emailLayout({
    eyebrow: "WELCOME",
    title: "Verify your email address",
    body: `<p style="margin:0;">Welcome to ${escapeHtml(appName)}. Enter this code to activate your account. It expires in 10 minutes.</p>`,
    code,
    notice: "If you did not create this account, you can safely ignore this email.",
  });

export const passwordResetTokenEmailTemplate = (token) =>
  emailLayout({
    eyebrow: "PASSWORD RESET",
    title: "Reset your password",
    body: `<p style="margin:0;">We received a request to reset your ${escapeHtml(appName)} password. This link expires in 10 minutes.</p>`,
    action: { url: getPasswordResetUrl(token), label: "Reset password" },
    notice: `If you did not request a password reset, you can safely ignore this email or contact us at <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.`,
  });

export const passwordResetNotificationEmailTemplate = () =>
  emailLayout({
    eyebrow: "SECURITY NOTICE",
    title: "Your password was changed",
    body: `<p style="margin:0;">This confirms that the password for your ${escapeHtml(appName)} account was changed successfully.</p>`,
    notice: `Did not make this change? Contact us immediately at <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.`,
  });

export const twoFactorEnabledEmailTemplate = () =>
  emailLayout({
    eyebrow: "SECURITY UPDATE",
    title: "Two-factor authentication is on",
    body: `<p style="margin:0;">Two-factor authentication has been enabled for your ${escapeHtml(appName)} account. You will now need a verification code when signing in.</p>`,
    notice: `Did not enable this? Contact us immediately at <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.`,
  });

export const twoFactorCodeEmailTemplate = (code) =>
  emailLayout({
    eyebrow: "TWO-FACTOR AUTHENTICATION",
    title: "Confirm your security change",
    body: "<p style=\"margin:0;\">Enter this code to continue. It expires in 10 minutes.</p>",
    code,
    notice: "Never share this code with anyone.",
  });

export const twoFactorSignInEmailTemplate = (code) =>
  emailLayout({
    eyebrow: "SIGN-IN VERIFICATION",
    title: "Confirm it’s you",
    body: `<p style="margin:0;">Use this code to complete your sign-in to ${escapeHtml(appName)}. It expires in 10 minutes.</p>`,
    code,
    notice: "Never share this code with anyone. If you did not try to sign in, reset your password and contact support.",
  });

export const emailVerificationTokenEmailTemplate = (code) =>
  emailLayout({
    eyebrow: "EMAIL VERIFICATION",
    title: "Verify your email address",
    body: "<p style=\"margin:0;\">Use this code to verify your email address. It expires in 1 hour.</p>",
    code,
    notice: "If you did not request this verification, you can safely ignore this email.",
  });

export const accountDeactivatedEmailTemplate = () =>
  emailLayout({
    eyebrow: "ACCOUNT UPDATE",
    title: "Your account has been deactivated",
    body: `<p style="margin:0;">Your ${escapeHtml(appName)} account is now deactivated. You will not be able to sign in until it is reactivated.</p>`,
    notice: `If you did not request this change, contact us immediately at <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.`,
  });

export const accountReactivatedEmailTemplate = () =>
  emailLayout({
    eyebrow: "ACCOUNT UPDATE",
    title: "Your account is active again",
    body: `<p style="margin:0;">Your ${escapeHtml(appName)} account has been reactivated. You can now sign in and continue using the service.</p>`,
    notice: `If you did not request this change, contact us immediately at <a href="mailto:${escapeHtml(supportEmail)}" style="color:#4f46e5;">${escapeHtml(supportEmail)}</a>.`,
  });

export const accountDeactivatedEmailcodeTemplate = (code) =>
  emailLayout({
    eyebrow: "ACCOUNT UPDATE",
    title: "Confirm account deactivation",
    body: "<p style=\"margin:0;\">Enter this code to deactivate your account. It expires in 10 minutes.</p>",
    code,
    notice: "If you did not request this change, you can safely ignore this email.",
  });

export const accountActivateEmailcodeTemplate = (code) =>
  emailLayout({
    eyebrow: "ACCOUNT UPDATE",
    title: "Confirm account reactivation",
    body: "<p style=\"margin:0;\">Enter this code to reactivate your account. It expires in 10 minutes.</p>",
    code,
    notice: "If you did not request this change, you can safely ignore this email.",
  });
