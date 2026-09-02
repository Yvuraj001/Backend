import { z } from "zod";
import { User } from "../models/userModel.js";
import bcrypt from "bcrypt";
import { generateCookies } from "../lib/generateCookies/cookies.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import {
  sendsignupEmailTemplate,
  sendpasswordResetNotificationEmailTemplate,
  sendpasswordResetTokenEmailTemplate,
  sendtwoFactorCodeEmailTemplate,
  sendtwoFactorSignInEmailTemplate,
  sendtwoFactorEnabledEmailTemplate,
  sendaccountactivateCodeemail,
  sendaccountdeactivateCodeemail,
  sendaccountdeactivatenotification,
  sendaccountactivatenotification,
} from "../lib/email/email.js";
const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .email("Please provide a valid email!");

const zodEmail = z.object({
  email: emailSchema,
});

const zodVerification = z.object({
  verificationToken: z.number("Provide a valid number!"),
});

const zodPassword = z.object({
  password: z.string().min(6, "Password must me atleast 6 digit long!"),
});

const zodResetPass = z.object({
  password: z.string().min(6, "Password must me atleast 6 digit long!"),
  verificationToken: z.number("Provide a valid number!"),
});

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

    await sendsignupEmailTemplate(result.data.email, verificationToken).catch(
      (err) => {
        res.status(500).json({
          success: false,
          message: "Failed to send verification Token email",
        });

        console.log("Failed to send verification Token email:", err.message);
      },
    );
    return res.status(201).json({
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
      await generateCookies(res, isUser._id, req);
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
    await sendtwoFactorSignInEmailTemplate(isUser.email, signInToken);
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
      return res
        .status(404)
        .json({ success: false, message: "Invalid email!" });
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

// ************************************************************************************

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
    await sendaccountactivateCodeemail(isUser.email, verificationToken).catch(
      (err) => {
        res.status(500).json({
          success: false,
          message: "Failed to send verification Token email",
        });

        console.log("Failed to send verification Token email:", err.message);
      },
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
    await sendaccountdeactivateCodeemail(isUser.email, verificationToken).catch(
      (err) => {
        res.status(500).json({
          success: false,
          message: "Failed to send verification Token email",
        });

        console.log("Failed to send verification Token email:", err.message);
      },
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

//  2FA enable initilazation
export const initilaze_enable_2fa = async (req, res) => {
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
    const twofaToken = crypto.randomInt(10000000, 100000000);
    isUser.twofaEnableToken = twofaToken;
    isUser.twofaEnableTokenExpiresAt = Date.now() + 600 * 1000; // 10 min

    await isUser.save();
    await sendtwoFactorCodeEmailTemplate(isUser.email, twofaToken).catch(
      (err) => {
        res.status(500).json({
          success: false,
          message: "Failed to send verification Token email",
        });

        console.log("Failed to send verification Token email:", err.message);
      },
    );
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

    const twofaToken = crypto.randomInt(10000000, 100000000);
    isUser.twofaDisableToken = twofaToken;
    isUser.twofaDisableExpiresAt = Date.now() + 600 * 1000; // 10 min

    await isUser.save();
    await sendtwoFactorCodeEmailTemplate(isUser.email, twofaToken).catch(
      (err) => {
        res.status(500).json({
          success: false,
          message: "Failed to send verification Token email",
        });

        console.log("Failed to send verification Token email:", err.message);
      },
    );
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

// ************************************************************************************

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
      await generateCookies(res, isUser._id, req);
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
      res.clearCookie("pass");
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
      await generateCookies(res, isUser._id, req);
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
      isUser.lastlogin = Date.now();
      await isUser.save();
      await generateCookies(res, isUser._id, req);
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

// re-generates verificatoin codes
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

// v1 of generate_2fa_verification_code
export const generate_2fa_verification_code = async (req, res) => {
  try {
    const token = req.cookies.pass;
    const matchToken = jwt.verify(token, process.env.JWT_SECRET);
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
