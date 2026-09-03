import crypto from "crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { User } from "../models/userModel.js";
import { Session } from "../models/sessionModel.js";
import {
  cookiesOptions,
  generateCookies,
} from "../lib/generateCookies/cookies.js";
import { zodEmail } from "../utils/zodConfig.js";
import {
  sendsignupEmailTemplate,
  sendtwoFactorSignInEmailTemplate,
} from "../lib/email/email.js";
import { emailSchema } from "../utils/zodConfig.js";

// signup function
export const signup = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide required feilds",
      });
    }

    const userData = z.object({
      email: emailSchema,
      password: z.string().min(6, "Password must me atleast 6 digit long"),
    });

    const result = userData.safeParse({ email: email, password: password });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      email: result.data.email,
    });

    if (isUser) {
      return res
        .status(409)
        .json({ success: false, message: "User already exists!" });
    }

    const hashedPassword = await bcrypt.hash(result.data.password, 10);
    const verificationToken = crypto.randomInt(10000000, 100000000);

    // saving user
    const name = result.data.email.split("@")[0];
    const newUser = new User({
      name: name,
      email: result.data.email,
      password: hashedPassword,
      verificationToken: parseInt(verificationToken),
      verificationTokenExpiresAt: Date.now() + 600 * 1000, // 10 minutes
    });

    try {
      await newUser.save();
    } catch (error) {
      if (error?.code === 11000) {
        return res
          .status(409)
          .json({ success: false, message: "User already exists!" });
      }

      throw error;
    }
    let emailError;
    await sendsignupEmailTemplate(result.data.email, verificationToken).catch(
      (err) => {
        emailerror = err;
        console.log("Failed to send verification Token email:", err.message);
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    return res.status(200).json({
      success: true,
      message: "Verify your account to to complete signup!",
    });
  } catch (error) {
    console.log("Error while creating user!", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};
// login function
export const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email or password not provided!",
      });
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
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    if (isUser.isActive === false) {
      return res.status(403).json({
        success: false,
        message: "Your account is deactivated!!",
      });
    }
    if (isUser.isVerified === false) {
      return res.status(403).json({
        success: false,
        message: "Verify your account to login!",
      });
    }

    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    if (!isUser.twofa) {
      await generateCookies(res, isUser._id);
      const updateEntry = await User.findOneAndUpdate(
        { email: result.data.email },
        { $set: { lastlogin: Date.now() } },
      );
      return res
        .status(200)
        .json({ success: true, message: "login sucessfull!" });
    }

    const signInToken = crypto.randomInt(10000000, 100000000);
    isUser.twofaSignInToken = signInToken;
    isUser.twofaSignInTokenExpiresAt = Date.now() + 600 * 1000; // 10 min
    await isUser.save();
    let emailError;
    await sendtwoFactorSignInEmailTemplate(isUser.email, signInToken).catch(
      (err) => {
        emailError = err;
        console.log(
          "Failed to send 2FA signin verification Token email:",
          err.message,
        );
      },
    );
    if (emailError) {
      return res.status(500).json({
        success: false,
        message: "Failed to send verification token email!",
      });
    }
    return res.status(200).json({ success: true, message: "Verify yourself!" });
  } catch (error) {
    console.log("Error while logining user: ", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};
// logout function
export const logout = async (req, res) => {
  // de-authenticating tokens
  try {
    const refreshCookie = req.cookies.pass;
    const match = await jwt.verify(
      refreshCookie,
      process.env.JWT_REFRESH_SECRET,
    );
    if (match.userId) {
      const session = await Session.findOne({
        userId: match.userId,
        refreshToken: refreshCookie,
        isValid: true,
      });

      if (session) {
        session.isValid = false;
        session.refreshToken = undefined;
        await session.save();
      }
    }
  } catch (error) {
    console.log("Falied to update session validdation:", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Failed to logout, try again later.." });
  }
  // deleting cookies
  try {
    res.clearCookie("pass", cookiesOptions);
    res.clearCookie("ref", cookiesOptions);

    return res
      .status(200)
      .json({ success: true, message: "Logout successfull!" });
  } catch (error) {
    console.log("Error while logout user", error.message);
    res
      .status(500)
      .json({ success: false, message: "Failed to logout, try again later.." });
  }
};
