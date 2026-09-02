import jwt from "jsonwebtoken";
import { Session } from "../../models/sessionModel.js";
import crypto from "crypto";
import { User } from "../../models/userModel.js";
import { cookiesOptions } from "../generateCookies/cookies.js";

export const verifyAuth = async (req, res, next) => {
  // if access token is present and valid (ref)
  try {
    const accessCookie = req.cookies.ref;
    const match = await jwt.verify(accessCookie, process.env.JWT_SECRET);
     
    if (match) {
      return res.json({
        success: true,
        userId: match.userId || "failed to show userID",
        message: "You are already logged in!",
      });
    }

  } catch (error) {
    res.clearCookie("ref")
    console.log("(ignore)-access token might not be found!", error.message);
  }
  // if refresh token is present (pass)
  try {
    const refreshCookie = req.cookies.pass;
    const match = await jwt.verify(
      refreshCookie,
      process.env.JWT_REFRESH_SECRET,
    );

    const session = await Session.findOne({
      userId: match.userId,
      refreshToken: refreshCookie,
      isValid: true,
      expiresAt: { $gt: Date.now() },
    });
    if (!session) {
      res.clearCookie("pass");
      res.clearCookie("ref");
      return next();
    }
    const newAccessToken = crypto.randomBytes(64).toString("hex");
    const accessToken = await jwt.sign(
      { newAccessToken },
      process.env.JWT_SECRET,
      {
        expiresIn: Date.now() + 15 * 60 * 1000,
      },
    );

    res.cookie("ref", accessToken, {
      ...cookiesOptions,
      maxAge: 15 * 60 * 1000,
    });
    return res.json({
      success: true,
      userId: match.userId,
      message: "You are already logged in!",
    });
  } catch (error) {
        res.clearCookie("pass");
        res.clearCookie("ref");
    console.log("(ignore)-Both cookies are absent", error.message)
    return next()
  }
 };

// export const verifyAuth = async (req, res, next) => {
//   try {
//     const cookie = await req.cookies.pass;
//     const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);

//     if (tokenMatched.userId) {
//       return res.json({
//         success: true,
//         userId: tokenMatched.userId,
//         message: "You are already logged in!",
//       });
//     }

//   } catch (error) {
//     res.clearCookie("pass");
//     console.log("(ignore)-the error in verifyAuth", error.message);

//     return next();
//   }
// }
