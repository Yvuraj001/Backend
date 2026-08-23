import { z } from "zod";
import { User } from "../models/userModel.js";
import bcrypt from "bcrypt";
import { generateCookies } from "../lib/generateCookies/index.js";
import crypto from "crypto";
import jwt from 'jsonwebtoken'
import {
  sendsignupEmailTemplate,
  sendpasswordResetNotificationEmailTemplate,
  sendpasswordResetTokenEmailTemplate,
  sendtwoFactorCodeEmailTemplate,
  sendtwoFactorEnabledEmailTemplate,
  sendaccountactivateCodeemail,
  sendaccountdeactivateCodeemail,
  sendaccountdeactivatenotification,
  sendaccountactivatenotification,
} from "../lib/email/email.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";


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
      email: z.email("Please provide a valid email"),
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
    await sendsignupEmailTemplate(result.data.email, verificationToken).catch(
      (err) => console.log("Failed to send signup email:", err.message),
    );
    return res.status(201).json({
      success: true,
      message: "User created successfully!",
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
    const isUser = await User.findOne({ email: email });

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
    return res
      .status(200)
      .json({ success: true, message: "login sucessfull!" });
  } catch (error) {
    console.log("Error while logining user: ", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};
// logout function
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
      .status(500)
      .json({ success: false, message: "Failed to logout, try again later.." });
  }
};

// ************************************************************************************

// initialise forget password (sets reset code and send email to user)
export const forgotMe = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Provide email!" });
    }
    const isUser = await User.findOne({ email: email });
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
// resets the password
export const resetPassword = async (req, res) => {
  try {
    const { password, token } = req.body;
    if (!password || !token) {
      return res.status(400).json({
        success: false,
        message: "Provide all the require feild!",
      });
    }
    const userData = z.object({
      password: z.string().min(6, "Password must me atleast 6 digit long"),
    });

    const result = userData.safeParse({ password: password });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({
      passwordResetToken: token,
      passwordResetTokenExpiresAt: { $gt: Date.now() },
    });
    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Invalid  or expired token!",
      });
    }

    if (parseInt(token) === parseInt(isUser.passwordResetToken)) {
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

// ************************************************************************************

// initialize re-activation of user
export const activateMe = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all the required feild!" });
    }
    const isUser = await User.findOne({ email: email });
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
    const verificationToken = crypto.randomInt(100000, 1000000);
    isUser.activationCode = verificationToken;
    isUser.activationCodeExpiresAt = Date.now() + 600 * 1000; // 10 minutes

    await isUser.save();
    await sendaccountactivateCodeemail(isUser.email, verificationToken).catch(
      (err) => console.log("error sending activation code email", err.message),
    );
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
export const deactivateMe = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all the required feild!" });
    }
    const isUser = await User.findOne({ email: email });
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
    const verificationToken = crypto.randomInt(100000, 1000000);
    isUser.deactivationCode = verificationToken;
    isUser.deactivationCodeExpiresAt = Date.now() + 600 * 1000; // 10 minutes

    await isUser.save();
    await sendaccountdeactivateCodeemail(isUser.email, verificationToken).catch(
      (err) =>
        console.log("error sending deactivation code email", err.message),
    );
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

// ************************************************************************************

//  2FA initilazation
export const initilaze2FA = async (req, res) => {
  try {
     const cookie = await req.cookies.pass;
     const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);
    if (!tokenMatched) {
      return res.json({
        success: false,
        message: "Please signin to enable 2FA!",
      });
    }

    const isUser = await User.findOne({ _id: tokenMatched.userId });
    if (!isUser) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid email!" });
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

    if (isUser.twofa) {
      return res
        .status(409)
        .json({ success: false, message: "2FA already enbaled!" });
    }

    const twofaToken = crypto.randomInt(100000, 1000000);
    isUser.twofaToken = twofaToken;
    isUser.twofaTokenExpiresAt = Date.now() + 15 * 60 * 1000; // 15 min

    await isUser.save();

    res
      .status(200)
      .json({ success: true, message: "2FA code sent to your email!" });

    await sendtwoFactorCodeEmailTemplate(twofaToken).catch((err) => {
      console.log("Error while sending 2FA code!", err.message);
    });
  } catch (error) {
    console.log("Error while sending 2FA code", error.message);
    return res.status(500).json({
      success: false,
      message: "Failed to send 2FA code. Signin to use this feature!",
    });
  }
};

// ************************************************************************************

// verify user's email
export const verifyEmail = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all required feild!" });
    }

    const isUser = await User.findOne({
      verificationToken: verificationToken,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
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
// de-activates the user
export const verifyDeactivation = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide all required feild!" });
    }

    const isUser = await User.findOne({
      deactivationCode: verificationToken,
      deactivationCodeExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (parseInt(verificationToken) === isUser.deactivationCode) {
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
// activates the user
export const verifyActivation = async (req, res) => {
  try {
    const { verificationToken } = req.body;

    if (!verificationToken) {
      return res
        .status(400)
        .json({ success: false, message: "Provide required feild!" });
    }

    const isUser = await User.findOne({
      activationCode: verificationToken,
      activationCodeExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Verification code is invalid or expired!",
      });
    }

    if (parseInt(verificationToken) === isUser.activationCode) {
      isUser.isActive = true;
      isUser.activationCode = undefined;
      isUser.activationCodeExpiresAt = undefined;

      await isUser.save();
      await sendaccountactivatenotification(isUser.email).catch((err) => {
        console.log("error while sending activation email", err.message);
      });
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
// verifies 2FA and Enables/Disables
export const verify2FA = async (req, res) => {
  try {
    // type: enable or disable
    const { verificationToken, type } = req.body;

    if (!verificationToken || !type) {
      return res.status(400).json({
        success: false,
        message: "Provide verification token and type!",
      });
    }

    if (type !== "enable" && type !== "disable") {
      return res
        .status(400)
        .json({ success: false, message: "Type must be enable or disable!" });
    }

    const isUser = await User.findOne({
      twofaToken: verificationToken,
      twofaTokenExpiresAt: { $gt: Date.now() },
    });

    if (!isUser) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired code!",
      });
    }

    if (parseInt(verificationToken) === isUser.twofaToken) {
      isUser.twofa = type === "enable" ? true : false;
      isUser.twofaToken = undefined;
      isUser.twofaTokenExpiresAt = undefined;

      await isUser.save();
      return res.status(200).json({
        success: true,
        message:
          type === "enable"
            ? "2FA enabled sucessfully!"
            : "2FA disabled sucessfully",
      });
    }

    return res.status(400).json({
      success: false,
      message:
        type === "enable" ? "Failed to enable 2FA" : "Failed to disable 2FA",
    });
  } catch (error) {
    console.log("Error while enabling/disablign 2FA", error.message);
    return res
      .status(500)
      .json({ success: false, message: "Something went wrong!" });
  }
};

