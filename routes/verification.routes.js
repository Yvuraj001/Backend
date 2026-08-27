import express from "express";
import {
  verifyEmail,
  resetPassword,
  verifyActivation,
  verifyDeactivation,
  verify2FA,
} from "../controller/controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";
import jwt from 'jsonwebtoken'
import rateLimit from "express-rate-limit";
export const VerificationRouter = express.Router();

const limiter = rateLimit({
  windowMs: 16 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});
// verifies crossponding routes after their initalisation from security.routes.js
VerificationRouter.get("/verify",limiter,  async (req, res) => {
  try {
    const cookie = await req.cookies.pass;
    const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);
    if (tokenMatched.userId) {
      return res.json({
        success: true,
        userId: tokenMatched.userId,
        message: "You arelogged in!",
      });
    }
  } catch (error) {
    console.log("the error in verifyAuth or not logged in", error.message);

    return res.json({
      success: false,
      message: "Not logged in!",
    });
  }
});
VerificationRouter.post("/verifyEmail",limiter,  verifyEmail);
VerificationRouter.post("/verifyForget",limiter,  resetPassword);
VerificationRouter.post("/verifyDeactivation", limiter, verifyDeactivation);
VerificationRouter.post("/verifyActivation", limiter, verifyActivation);
// takes type: 'enable' to enable or nothing for disable
VerificationRouter.post("/verify2FA",limiter,  verify2FA);
