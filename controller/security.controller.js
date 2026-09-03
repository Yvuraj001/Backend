import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { User } from "../models/userModel.js";
import { zodEmail } from "../utils/zodConfig.js";
import {
  sendpasswordResetTokenEmailTemplate,
  sendtwoFactorCodeEmailTemplate,
  sendaccountactivateCodeemail,
  sendaccountdeactivateCodeemail,
} from "../lib/email/email.js";

// initialise forget password
export const initalize_forget_user = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Provide email!" });
    }
    const result = zodEmail.safeParse({ email: email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({ email: result.data.email });
    if (!isUser) {
      return res.status(200).json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }
    if (isUser.isActive === false) {
      return res
        .status(403)
        .json({ success: false, message: "Account is de-activated!" });
    }

    const resetToken = crypto.randomBytes(25).toString("hex");
    isUser.passwordResetToken = resetToken;
    isUser.passwordResetTokenExpiresAt = Date.now() + 600 * 1000; // 10 min
    await isUser.save();

    let emailError;
    await sendpasswordResetTokenEmailTemplate(isUser.email, resetToken).catch(
      (err) => {
        emailError = err;
        console.log("Failed to send password reset email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send password reset email!",
      });
    }
    return res.status(200).json({
      success: true,
      message: "Password reset link sent to your email!",
    });
  } catch (error) {
    console.log("Error while requesting password reset", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to send reset code!" });
  }
};

// initialize re-activation of user
export const initalize_re_activate_user = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all the required feild!" });
    }

    const result = zodEmail.safeParse({ email: email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({ email: result.data.email });
    if (!isUser)
      return res.status(401).json({
        success: false,
        message: "Provide the valid email or password!",
      });

    if (isUser.isActive === true) {
      return res.status(409).json({
        success: false,
        message: "Account is already activated!",
      });
    }
    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass)
      return res.status(401).json({
        success: false,
        message: "Provide the valid email or password!",
      });
    const verificationToken = crypto.randomInt(10000000, 100000000);
    isUser.activationCode = verificationToken;
    isUser.activationCodeExpiresAt = Date.now() + 600 * 1000; // 10 minutes

    await isUser.save();
    let emailError;
    await sendaccountactivateCodeemail(isUser.email, verificationToken).catch(
      (err) => {
        emailError = err;

        console.log("Failed to send verification Token email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    return res
      .status(200)
      .json({ success: true, message: "Activation Code sent!" });
  } catch (error) {
    console.log("Error while activating user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to activate user!" });
  }
};
// initialize de-activation of user
export const initalize_de_activate_user = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all the required feild!" });
    }
    const result = zodEmail.safeParse({ email: email });
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({ email: result.data.email });
    if (!isUser)
      return res.status(401).json({
        success: false,
        message: "Provide the valid email or password!",
      });

    if (isUser.isActive === false) {
      return res.status(409).json({
        success: false,
        message: "Account is already de-activated!",
      });
    }
    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass)
      return res.status(401).json({
        success: false,
        message: "Provide the valid email or password!",
      });
    const verificationToken = crypto.randomInt(10000000, 100000000);
    isUser.deactivationCode = verificationToken;
    isUser.deactivationCodeExpiresAt = Date.now() + 600 * 1000; // 10 minutes

    await isUser.save();
    let emailError;
    await sendaccountdeactivateCodeemail(isUser.email, verificationToken).catch(
      (err) => {
        emailError = err;

        console.log("Failed to send verification Token email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    return res
      .status(200)
      .json({ success: true, message: "Deactivation Code sent!" });
  } catch (error) {
    console.log("Error while deactivating user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to deactivate user!" });
  }
};

//  2FA enable initilazation
export const initilaze_enable_2fa = async (req, res) => {
  try {
    const cookie = await req.cookies.pass;
    const tokenMatched = await jwt.verify(
      cookie,
      process.env.JWT_REFRESH_SECRET,
    );
    if (!tokenMatched) {
      return res.json({
        success: false,
        message: "Please signin to enable 2FA!",
      });
    }

    const isUser = await User.findOne({ _id: tokenMatched.userId });
    if (!isUser) {
      return res.status(200).json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }
    if (!isUser.isVerified) {
      return res.status(403).json({
        success: false,
        message: "First verify your account to enable 2FA!",
      });
    }
    if (!isUser.isActive) {
      return res
        .status(403)
        .json({ success: false, message: "Your Account is de-activated!" });
    }

    if (isUser.twofa) {
      return res.status(409).json({
        success: false,
        message: "Your Account has already enabled 2FA!",
      });
    }
    const twofaToken = crypto.randomInt(10000000, 100000000);
    isUser.twofaEnableToken = twofaToken;
    isUser.twofaEnableTokenExpiresAt = Date.now() + 600 * 1000; // 10 min

    await isUser.save();
    let emailError;
    await sendtwoFactorCodeEmailTemplate(isUser.email, twofaToken).catch(
      (err) => {
        emailError = err;

        console.log("Failed to send verification Token email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    res
      .status(200)
      .json({ success: true, message: "2FA code sent to your email!" });
  } catch (error) {
    console.log("Error while sending 2FA code", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to send 2FA code. Signin to use this feature!",
    });
  }
};
// 2FA disable initilazation
export const initilaze_disable_2fa = async (req, res) => {
  try {
    const cookie = await req.cookies.pass;
    const tokenMatched = await jwt.verify(
      cookie,
      process.env.JWT_REFRESH_SECRET,
    );
    if (!tokenMatched) {
      return res.json({
        success: false,
        message: "Please signin to enable 2FA!",
      });
    }

    const isUser = await User.findOne({ _id: tokenMatched.userId });
    if (!isUser) {
      return res.status(200).json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }
    if (!isUser.isVerified) {
      return res.status(403).json({
        success: false,
        message: "First verify your account to enable 2FA!",
      });
    }
    if (!isUser.isActive) {
      return res
        .status(403)
        .json({ success: false, message: "Your Account is de-activated!" });
    }

    const twofaToken = crypto.randomInt(10000000, 100000000);
    isUser.twofaDisableToken = twofaToken;
    isUser.twofaDisableExpiresAt = Date.now() + 600 * 1000; // 10 min

    await isUser.save();
    let emailError;
    await sendtwoFactorCodeEmailTemplate(isUser.email, twofaToken).catch(
      (err) => {
        emailError = err;

        console.log("Failed to send verification Token email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    res
      .status(200)
      .json({ success: true, message: "2FA code sent to your email!" });
  } catch (error) {
    console.log("Error while sending 2FA code", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to send 2FA code. Signin to use this feature!",
    });
  }
};
