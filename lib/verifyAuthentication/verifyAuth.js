import jwt from "jsonwebtoken";
import { Session } from "../../models/sessionModel.js";
import { User } from "../../models/userModel.js";
import { cookiesOptions, isCrossSite } from "../generateCookies/cookies.js";

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
    res.clearCookie("ref", cookiesOptions);
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
      res.clearCookie("pass", cookiesOptions);
      res.clearCookie("ref", cookiesOptions);
      return next();
    }

    const accessToken = await jwt.sign(
      { userId: session.userId },
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
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
    res.clearCookie("pass", cookiesOptions);
    res.clearCookie("ref", cookiesOptions);
    console.log("(ignore)-Both cookies are absent", error.message);
    return next();
  }
};
// middleware for upload avatar route
export const requireAuth = async (req, res, next) => {
  try {
    const accessCookie = req.cookies.ref;
    const { userId } = jwt.verify(accessCookie, process.env.JWT_SECRET);
    req.userId = userId;
    return next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Sign in to continue!" });
  }
};
