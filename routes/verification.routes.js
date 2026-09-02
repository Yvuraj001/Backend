import express from "express";
import {
  verify_user_email,
  verify_forget_user,
  verify_de_activate_user,
  verify_re_activate_user,
  verify_2fa_disable,
  verify_2fa_enable,
  verify_2fa_signin,
} from "../controller/controller.js";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
export const VerificationRouter = express.Router();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});
VerificationRouter.get("/verify", limiter, async (req, res) => {
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
    console.log("You arn't not logged in", error.message);

    return res.json({
      success: false,
      message: "Not logged in!",
    });
  }
});
VerificationRouter.post("/email/verify", limiter, verify_user_email);
VerificationRouter.post(
  "/forgot-user/verify/:auth_token",
  limiter,
  verify_forget_user,
);
VerificationRouter.post(
  "/deactivate-user/verify",
  limiter,
  verify_de_activate_user,
);
VerificationRouter.post(
  "/activate-user/verify",
  limiter,
  verify_re_activate_user,
);
VerificationRouter.post("/2fa/enable/verify", limiter, verify_2fa_enable);
VerificationRouter.post("/2fa/disable/verify", limiter, verify_2fa_disable);
VerificationRouter.post("/2fa/signin/verify", limiter, verify_2fa_signin);
