import jwt from "jsonwebtoken";
import crypto from "crypto";
import { User } from "../models/userModel.js";
import { initalize_forget_user } from "./security.controller.js";
import { zodEmail } from "../utils/zodConfig.js";
import {
  sendsignupEmailTemplate,
  sendtwoFactorCodeEmailTemplate,
  sendtwoFactorSignInEmailTemplate,
  sendaccountactivateCodeemail,
  sendaccountdeactivateCodeemail,
} from "../lib/email/email.js";

export const generate_email_verification_code = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.json({ success: false, message: "Provide a valid email!" });
    }
    const result = zodEmail.safeParse({ email: email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({ email: email });

    if (!isUser) {
      return res.json({ success: false, message: "Provide a valid email!" });
    }

    const newToken = crypto.randomInt(10000000, 100000000);
    if (!isUser.isVerified && isUser.isActive) {
      isUser.verificationToken = newToken;
      isUser.verificationTokenExpiresAt = Date.now() + 600 * 1000; // 10 minutes
      await isUser.save();
      let emailError;
      await sendsignupEmailTemplate(isUser.email, newToken).catch((err) => {
        emailError = err;
        console.log("Failed to send verification token email:", err.message);
      });
      if (emailError) {
        return res.status(500).json({
          success: false,
          message: "Failed to send verification token email!",
        });
      }
      return res
        .status(200)
        .json({ success: true, message: "Resent successfull!" });
    }

    return res
      .status(402)
      .json({ success: false, message: "Already verified!" });
  } catch (error) {
    console.log("Error in resend email verification code", error.messagae);
    return res.status(500).json({
      success: false,
      message: "Something went wrong while sending verification code!",
    });
  }
};

export const generate_reset_verification_code = async (req, res) => {
  return initalize_forget_user(req, res);
};

export const generate_activation_verification_code = async (req, res) => {
  try {
    const result = zodEmail.safeParse({ email: req.body.email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((issue) => issue.message).join(", "),
      });
    }

    const isUser = await User.findOne({ email: result.data.email });
    if (!isUser) {
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }
    if (isUser.isActive) {
      return res.status(409).json({
        success: false,
        message: "Account is already active!",
      });
    }

    const code = crypto.randomInt(10000000, 100000000);
    isUser.activationCode = code;
    isUser.activationCodeExpiresAt = Date.now() + 600 * 1000;
    await isUser.save();
    let emailError;
    await sendaccountactivateCodeemail(isUser.email, code).catch((err) => {
      emailError = err;
      console.log("Failed to send activation code email:", err.message);
    });
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send activation code email!",
      });
    }

    return res.json({ success: true, message: "Activation code resent!" });
  } catch (error) {
    console.log("Error resending activation code:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to resend activation code!",
    });
  }
};

export const generate_deactivation_verification_code = async (req, res) => {
  try {
    const result = zodEmail.safeParse({ email: req.body.email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((issue) => issue.message).join(", "),
      });
    }

    const isUser = await User.findOne({ email: result.data.email });
    if (!isUser) {
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }
    if (!isUser.isActive) {
      return res.status(409).json({
        success: false,
        message: "Account is already deactivated!",
      });
    }

    const code = crypto.randomInt(10000000, 100000000);
    isUser.deactivationCode = code;
    isUser.deactivationCodeExpiresAt = Date.now() + 600 * 1000;
    await isUser.save();

    let emailError;
    await sendaccountdeactivateCodeemail(isUser.email, code).catch((err) => {
      emailError = err;
      console.log("Failed to send deactivation code email:", err.message);
    });
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send deactivation code email!",
      });
    }

    return res.json({ success: true, message: "Deactivation code resent!" });
  } catch (error) {
    console.log("Error resending deactivation code:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to resend deactivation code!",
    });
  }
};

export const generate_2fa_verification_code = async (req, res) => {
  try {
    const token = req.cookies.pass;
    const matchToken = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    if (!matchToken) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to resend a 2FA code!",
      });
    }
    const { type } = req.body;
    if (!["enable", "disable", "signin"].includes(type)) {
      return res.status(400).json({
        success: false,
        message: "2FA type must be provided!",
      });
    }

    if (type === "signin") {
      const isUser = await User.findOne({
        _id: matchToken.userId,
        twofa: true,
      });

      if (!isUser) {
        return res.status(400).json({
          success: false,
          message: "No pending two-factor sign-in was found!",
        });
      }

      const code = crypto.randomInt(10000000, 100000000);
      isUser.twofaSignInToken = code;
      isUser.twofaSignInTokenExpiresAt = Date.now() + 600 * 1000;
      await isUser.save();
      let emailError;
      await sendtwoFactorSignInEmailTemplate(isUser.email, code).catch(
        (err) => {
          emailError = err;
          console.log("Failed to send 2FA sign-in email:", err.message);
        },
      );
      if (emailError) {
        return res.status(500).json({
          success: false,
          message: "Failed to send 2FA sign-in code email!",
        });
      }
      return res.json({ success: true, message: "Sign-in code resent!" });
    }

    const isUser = await User.findById(matchToken.userId);
    if (!isUser || !isUser.isVerified || !isUser.isActive) {
      return res.status(403).json({
        success: false,
        message: "Your account cannot change 2FA settings right now!",
      });
    }
    if (
      (type === "enable" && isUser.twofa) ||
      (type === "disable" && !isUser.twofa)
    ) {
      return res.status(409).json({
        success: false,
        message: `2FA is already ${type === "enable" ? "enabled" : "disabled"}!`,
      });
    }

    const code = crypto.randomInt(10000000, 100000000);
    if (type === "enable") {
      isUser.twofaEnableToken = code;
      isUser.twofaEnableTokenExpiresAt = Date.now() + 600 * 1000;
    } else {
      isUser.twofaDisableToken = code;
      isUser.twofaDisableExpiresAt = Date.now() + 600 * 1000;
    }
    await isUser.save();
    let emailError;
    await sendtwoFactorCodeEmailTemplate(isUser.email, code).catch((err) => {
      emailError = err;
      console.log("Failed to send 2FA code email:", err.message);
    });
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send 2FA code email!",
      });
    }

    return res.json({ success: true, message: "2FA code resent!" });
  } catch (error) {
    console.log("Error resending 2FA code:", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to resend 2FA code. Sing-in to use this feature!",
    });
  }
};
