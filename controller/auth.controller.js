import { z } from "zod";
import { User } from "../models/userModel.js";
import bcrypt from "bcrypt";
import { generateCookies } from "../lib/generateCookies/index.js";
import crypto from "crypto";
import {
  sendsignupEmailTemplate,
  sendpasswordResetNotificationEmailTemplate,
  sendpasswordResetTokenEmailTemplate,
  sendtwoFactorCodeEmailTemplate,
  sendtwoFactorEnabledEmailTemplate,
} from "../lib/email/email.js";

// complete
export const signup = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({
        success: false,
        message: "Please provide required feilds",
      });
    }

    const userData = z.object({
      email: z.email("Please provide a valid email"),
      password: z.string().min(6, "Password must me atleast 6 digit long"),
    });

    const result = userData.safeParse({ email: email, password: password });

    if (!result.success) {
      return res.json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      email: result.data.email,
    });

    if (isUser) {
      return res.json({ success: false, message: "User already exists!" });
    }
    // pass and verfication tokens
    const hashedPassword = await bcrypt.hash(result.data.password, 10);
    const verificationToken = crypto.randomInt(100000, 1000000);

    // saving user
    const name = result.data.email.split("@")[0];
    const newUser = new User({
      name: name,
      email: result.data.email,
      password: hashedPassword,
      verificationToken: parseInt(verificationToken),
      verificationTokenExpiresAt: Date.now() + 3600 * 1000, // 1 hour
    });

    await newUser.save();

    // setting cookies

    await generateCookies(res, newUser._id);

    res.json({
      success: true,
      message: "User created successfully!",
    });
    sendsignupEmailTemplate(result.data.email, verificationToken).catch((err) =>
      console.log("Failed to send signup email:", err.message),
    );
  } catch (error) {
    console.log("Error while creating user!", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};

// complete
export const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({
        success: false,
        message: "Email or password not provided!",
      });
    }
    const isUser = await User.findOne({ email: email });

    if (!isUser) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    if (isUser.isActive === false) {
      return res.status(401).json({
        success: false,
        message: "Your account is deactivated!!",
      });
    }

    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    await generateCookies(res, isUser._id);
    const updateEntry = await User.findOneAndUpdate(
      { email: email },
      { $set: { lastlogin: Date.now() } },
    );
    res.status(200).json({ success: true, message: "login sucessfull!" });
  } catch (error) {
    console.log("Error while logining user: ", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};

// complete
export const logout = async (req, res) => {
  try {
    res.clearCookie("pass", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    return res
      .status(200)
      .json({ success: true, message: "Logout successfull!" });
  } catch (error) {
    console.log("Error while logout user", error.message);
    res
      .status(400)
      .json({ success: false, message: "Failed to logout, try again later.." });
  }
};

// complete
export const forgotMe = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Provide email!" });
    }
    const isUser = await User.findOne({ email });
    if (!isUser) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid email!" });
    }
    if (isUser.isActive === false) {
      return res
        .status(403)
        .json({ success: false, message: "Account is de-activated!" });
    }

    const resetToken = crypto.randomInt(100000, 1000000);
    isUser.passwordResetToken = resetToken;
    isUser.passwordResetTokenExpiresAt = Date.now() + 15 * 60 * 1000; // 15 min
    await isUser.save();

    res
      .status(200)
      .json({ success: true, message: "Reset code sent to your email!" });

    sendpasswordResetTokenEmailTemplate(isUser.email, resetToken).catch((err) =>
      console.log("Failed to send reset token email:", err.message),
    );
  } catch (error) {
    console.log("Error while requesting password reset", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to send reset code!" });
  }
};

// complete
export const verifyEmail = async (req, res) => {
  try {
    const { email, verificationToken } = req.body;

    if (!email || !verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all required feild!" });
    }

    const isUser = await User.findOne({
      email: email,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(500).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (parseInt(verificationToken) === isUser.verificationToken) {
      isUser.isVerified = true;
      isUser.verificationToken = undefined;
      isUser.verificationTokenExpiresAt = undefined;

      await isUser.save();
      return res
        .status(200)
        .json({ success: true, message: "Verification sucessfull!" });
    }

    return res
      .status(400)
      .json({ success: false, message: "Verification code is invalid!" });
  } catch (error) {
    console.log("Error while verifying user", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to verify!" });
  }
};

// complete
export const resetPassword = async (req, res) => {
  try {
    const { email, password, token } = req.body;
    if (!email || !password || !token) {
      return res.json({
        success: false,
        message: "Provide all the require feild!",
      });
    }
    const userData = z.object({
      password: z.string().min(6, "Password must me atleast 6 digit long"),
    });

    const result = userData.safeParse({ password: password });

    if (!result.success) {
      return res.json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      passwordResetToken: token,
      passwordResetTokenExpiresAt: { $gt: Date.now() },
    });
    if (!isUser) {
      return res.json({
        success: false,
        message: "Invalid  or expired token!",
      });
    }

    if (parseInt(token) === parseInt(isUser.passwordResetToken)) {
      const hashedPassword = await bcrypt.hash(password, 10);
      ((isUser.password = hashedPassword),
        (isUser.resetPassword = undefined),
        (isUser.resetPasswordTokenExpiresAt = undefined));

      await isUser.save();
      res
        .status(200)
        .json({ success: true, message: "Password reset sucessfull!" });

      await sendpasswordResetNotificationEmailTemplate(isUser.email).catch(
        (err) => console.log("Failed to send reset token email:", err.message),
      );
    }
  } catch (error) {
    console.log("Error while changin password!", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Failed to change password!" });
  }
};

export const deactivateMe = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(500)
        .json({ success: false, message: "Provide all the required feild!" });
    }
    const isUser = await User.findOne({ email: email });
    if (!isUser)
      return res.status(500).json({
        success: false,
        message: "Provide the valid email or password!",
      });

    if (isUser.isActive === false) {
      return res.status(500).json({
        success: false,
        message: "Account is already de-activated!",
      });
    }
    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass)
      return res.status(500).json({
        success: false,
        message: "Provide the valid email or password!",
      });

    // send activation code email here
    // verfication logic
    // send Account deactivating sucessfull email
    // after that:
    await User.findOneAndUpdate(
      { email: email },
      { $set: { isActive: false } },
    );

    return res
      .status(200)
      .json({ success: true, message: "Account deactivated!" });
  } catch (error) {
    console.log("Error while deleting user", error.message);
    return res.json({ success: false, message: "Failed to delete user!" });
  }
};

export const activateMe = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(500)
        .json({ success: false, message: "Provide all the required feild!" });
    }
    const isUser = await User.findOne({ email: email });
    if (!isUser)
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    if (isUser.isActive)
      return res
        .status(400)
        .json({ success: false, message: "Account is already active!" });

    const matchPass = await bcrypt.compare(password, isUser.password);

    if (!matchPass)
      return res.status(500).json({
        success: false,
        message: "Email or Password is incorrect!",
      });

    // send activation code here
    // verfication logic
    // send Account activated sucessfull
    // after that:
    await User.findOneAndUpdate({ email: email }, { $set: { isActive: true } });

    return res
      .status(200)
      .json({ success: true, message: "Account Activated successfully !" });
  } catch (error) {
    console.log("Error while Activating user", error.message);
    return res.json({ success: false, message: "Failed to Activate user!" });
  }
};

// 2fa