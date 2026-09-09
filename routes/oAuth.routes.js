import express from "express";
import crypto from "crypto";
import { User } from "../models/userModel.js";
import { oauth2Client } from "../utils/google.config.js";
import { generateCookies } from "../lib/generateCookies/cookies.js";

export const oAuthRoutes = express.Router();

oAuthRoutes.get("/initialize", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  req.session.state = state;

  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["openid", "email", "profile"],
    state: state,
  });

  res.redirect(url);
});

oAuthRoutes.get("/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res
        .status(400)
        .json({ success: false, message: "Access denied by user" });
    }
    if (!code || !state) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid callback url!" });
    }

    if (state !== req.session.state) {
      return res
        .status(403)
        .json({ success: false, message: "Unauthorize access!" });
    }
    // get acutal token from temp token
    const { tokens } = await oauth2Client.getToken(code);

    // verifying token
    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT,
    });
    const googleUser = ticket.getPayload();
    if (!googleUser) {
      return res
        .status(500)
        .json({ success: false, message: "Unexpected error occured!" });
    }

    const isUser = await User.findOne({ email: googleUser.email });
    if (isUser) {
      isUser.lastLogin = Date.now();
      await isUser.save();
      await generateCookies(res, isUser._id);
      return res.json({ success: true, message: "Login successful!" });
    }
    const newUser = new User({
      name: googleUser.name,
      email: googleUser.email,
      googleId: googleUser.sub,
      provider: "google",
      userAvatar: googleUser.picture,
      isVerified: googleUser.email_verified,
    });

    await newUser.save();
    await generateCookies(res, newUser._id);
    return res.json({ success: true, message: "Login successful!" });
  } catch (error) {
    console.log("Error while creating new user via google:", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Failed to create you account!" });
  }
});
