import bcrypt from "bcrypt";
import { User } from "../models/userModel.js";
import {
  cookiesOptions,
  isCrossSite,
  generateCookies,
} from "../lib/generateCookies/cookies.js";
import { zodVerification, zodPassword } from "../utils/zodConfig.js";
import {
  sendpasswordResetNotificationEmailTemplate,
  sendaccountdeactivatenotification,
  sendaccountactivatenotification,
} from "../lib/email/email.js";

// verify user's email
export const verify_user_email = async (req, res) => {
  try {
    const { verificationToken } = req.body;
    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all required feild!" });
    }
    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }

    const isUser = await User.findOne({
      verificationToken: result.data.verificationToken,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });
    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }
    if (isUser.isVerified) {
      return res.status(402).json({
        success: false,
        message: "Account already verified!",
      });
    }

    if (result.data.verificationToken === isUser.verificationToken) {
      isUser.isVerified = true;
      isUser.verificationToken = undefined;
      isUser.verificationTokenExpiresAt = undefined;

      await isUser.save();
      await generateCookies(res, isUser._id);
      return res
        .status(200)
        .json({ success: true, message: "Account created sucessfully!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Verification code is invalid!" });
  } catch (error) {
    console.log("Error while verifying user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to create you account!" });
  }
};
// de-activates the user
export const verify_de_activate_user = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all required feild!" });
    }

    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }

    const isUser = await User.findOne({
      deactivationCode: result.data.verificationToken,
      deactivationCodeExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (result.data.verificationToken === isUser.deactivationCode) {
      isUser.isActive = false;
      isUser.deactivationCode = undefined;
      isUser.deactivationCodeExpiresAt = undefined;

      await isUser.save();
      await sendaccountdeactivatenotification(isUser.email).catch((err) => {
        console.log(
          "error while sending deactivatoin notificatoin",
          err.message,
        );
      });
      res.clearCookie("pass", cookiesOptions);
      return res
        .status(200)
        .json({ success: true, message: "Accout deactivatation sucessfull!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Failed to deactivate your account!" });
  } catch (error) {
    console.log("Error while deactivating user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to Deactivate!" });
  }
};
// re-activates the user
export const verify_re_activate_user = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide required feild!" });
    }
    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      activationCode: result.data.verificationToken,
      activationCodeExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (result.data.verificationToken === isUser.activationCode) {
      isUser.isActive = true;
      isUser.activationCode = undefined;
      isUser.activationCodeExpiresAt = undefined;

      await isUser.save();
      await sendaccountactivatenotification(isUser.email).catch((err) => {
        console.log("error while sending activation email", err.message);
      });
      await generateCookies(res, isUser._id);
      return res
        .status(200)
        .json({ success: true, message: "Accout activation sucessfull!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Failed to activate your account!" });
  } catch (error) {
    console.log("Error while activation of user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to Activate!" });
  }
};
// verifies 2FA  Enables
export const verify_2fa_enable = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res.status(400).json({
        success: false,
        message: "Provide verification token!",
      });
    }

    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      twofaEnableToken: result.data.verificationToken,
      twofaEnableTokenExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired code!",
      });
    }
    if (isUser.twofa) {
      return res.status(200).json({
        success: true,
        message: "2FA already enabled!",
      });
    }
    if (result.data.verificationToken === isUser.twofaEnableToken) {
      isUser.twofa = true;
      isUser.twofaEnableToken = undefined;
      isUser.twofaEnableTokenExpiresAt = undefined;

      await isUser.save();
      return res.status(200).json({
        success: true,
        message: "2FA enabled sucessfully!",
      });
    }

    return res.status(400).json({
      success: false,
      message: "Failed to enable 2FA!",
    });
  } catch (error) {
    console.log("Error while enabling 2FA", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Something went wrong!" });
  }
};
// verifies 2FA disable
export const verify_2fa_disable = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res.status(400).json({
        success: false,
        message: "Provide verification token!",
      });
    }

    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      twofaDisableToken: result.data.verificationToken,
      twofaDisableExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired code!",
      });
    }
    if (isUser.twofa === false) {
      return res.status(402).json({
        success: false,
        message: "2FA already disabled!",
      });
    }

    if (result.data.verificationToken === isUser.twofaDisableToken) {
      isUser.twofa = false;
      isUser.twofaDisableToken = undefined;
      isUser.twofaDisableExpiresAt = undefined;

      await isUser.save();
      return res.status(200).json({
        success: true,
        message: "2FA disabled sucessfully!",
      });
    }

    return res.status(400).json({
      success: false,
      message: "Failed to disable 2FA!",
    });
  } catch (error) {
    console.log("Error while disabling 2FA", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Something went wrong!" });
  }
};
// 2FA Signin verification
export const verify_2fa_signin = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(200)
        .json({ success: false, message: "Provide verification token!" });
    }

    const result = zodVerification.safeParse({
      verificationToken: verificationToken,
    });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      twofaSignInToken: result.data.verificationToken,
      twofaSignInTokenExpiresAt: { $gt: Date.now() },
    });
    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (result.data.verificationToken === isUser.twofaSignInToken) {
      isUser.twofaSignInToken = undefined;
      isUser.twofaSignInTokenExpiresAt = undefined;
      isUser.lastLogin = Date.now();
      await isUser.save();
      await generateCookies(res, isUser._id);
      return res
        .status(200)
        .json({ success: true, message: "Login successfull!" });
    }

    return res
      .status(403)
      .json({ success: false, message: "Failed to verify your SignIn!" });
  } catch (error) {
    console.log("Error in 2Fa signin verification:", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Something went wrong!" });
  }
};
// resets the password
export const verify_forget_user = async (req, res) => {
  try {
    const { password } = req.body;
    const { auth_token } = req.params;
    if (!password || !auth_token) {
      return res.status(400).json({
        success: false,
        message: "Provide all the require feild!",
      });
    }

    const result = zodPassword.safeParse({
      password: password,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      passwordResetToken: auth_token,
      passwordResetTokenExpiresAt: { $gt: Date.now() },
    });
    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Invalid  or expired token!",
      });
    }

    if (auth_token === isUser.passwordResetToken) {
      const hashedPassword = await bcrypt.hash(password, 10);
      ((isUser.password = hashedPassword),
        (isUser.passwordResetToken = undefined),
        (isUser.passwordResetTokenExpiresAt = undefined));

      await isUser.save();
      await sendpasswordResetNotificationEmailTemplate(isUser.email).catch(
        (err) => console.log("Failed to send reset token email:", err.message),
      );
      return res
        .status(200)
        .json({ success: true, message: "Password reset sucessfull!" });
    }
    return res.status(400).json({
      success: false,
      message: "Failed to reset password, provide valid token!",
    });
  } catch (error) {
    console.log("Error while changin password!", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to change password!" });
  }
};
