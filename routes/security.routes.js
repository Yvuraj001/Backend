import express from "express";
import {
  deactivateMe,
  activateMe,
  forgotMe,
  initilaze2FA,
  generateAgain,
} from "../controller/controller.js";
import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 16 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

export const securityRoutes = express.Router();
// initalize forget password of user
securityRoutes.post("/forgot-user", limiter, forgotMe);
// initalize re-activation of user
securityRoutes.post("/activate-user", limiter, activateMe);
// initialize de-activation of user
securityRoutes.post("/deactivate-user", limiter, deactivateMe);
// initalize enable/disable of 2FA
securityRoutes.post("/mutate-2fa", limiter, initilaze2FA);

// resend codes

securityRoutes.post("/resend-code", limiter,  generateAgain);
