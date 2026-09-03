import express from "express";
import {
  verify_2fa_disable,
  verify_2fa_enable,
  verify_2fa_signin,
  verify_de_activate_user,
  verify_re_activate_user,
  verify_user_email,
  verify_forget_user,
} from "../controller/verfification.controller.js";
import rateLimit from "express-rate-limit";
import { get_auth } from "../utils/getAuth.js";
export const VerificationRouter = express.Router();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});
VerificationRouter.get("/verify", limiter, get_auth);
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
