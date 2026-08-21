import express from "express";
import {
  deactivateMe,
  activateMe,
  forgotMe,
  initilaze2FA,
} from "../controller/auth.controller.js";

export const securityRoutes = express.Router();
// initalize forget password of user
securityRoutes.post("/forgot-user", forgotMe);
// initalize re-activation of user
securityRoutes.post("/activate-user", activateMe);
// initialize de-activation of user
securityRoutes.post("/deactivate-user", deactivateMe);
// initalize enable/disable of 2FA
securityRoutes.post("/mutate-2fa", initilaze2FA);
