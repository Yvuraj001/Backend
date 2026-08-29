import express from "express";
import {
  initalize_de_activate_user,
  initalize_re_activate_user,
  initalize_forget_user,
  initilaze_disable_2fa,
  initilaze_enable_2fa,
  generate_2fa_verification_code,
  generate_activation_verification_code,
  generate_deactivation_verification_code,
  generate_email_verification_code,
  generate_reset_verification_code,
} from "../controller/controller.js";
import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 16 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

export const securityRoutes = express.Router();
// initalize forget password of user
securityRoutes.post("/forgot-user/start", limiter, initalize_forget_user);
// initalize re-activation of user
securityRoutes.post(
  "/activate-user/start",
  limiter,
  initalize_re_activate_user,
);
// initialize de-activation of user
securityRoutes.post(
  "/deactivate-user/start",
  limiter,
  initalize_de_activate_user,
);
// initalize 2fa enable
securityRoutes.post("/2fa/enable/start", limiter, initilaze_enable_2fa);
securityRoutes.post("/2fa/disable/start", limiter, initilaze_disable_2fa);
// resend verification codes
securityRoutes.post(
  "/resend/email-verification",
  limiter,
  generate_email_verification_code,
);
securityRoutes.post(
  "/resend/password-reset",
  limiter,
  generate_reset_verification_code,
);
securityRoutes.post("/resend/2fa", limiter, generate_2fa_verification_code);
securityRoutes.post(
  "/resend/activation",
  limiter,
  generate_activation_verification_code,
);
securityRoutes.post(
  "/resend/deactivation",
  limiter,
  generate_deactivation_verification_code,
);
