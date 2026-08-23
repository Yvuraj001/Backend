import express from "express";
import {
  verifyEmail,
  resetPassword,
  verifyActivation,
  verifyDeactivation,
  verify2FA,
} from "../controller/auth.controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";

export const VerificationRouter = express.Router();

// verifies crossponding routes after their initalisation from security.routes.js
VerificationRouter.get("/verify", verifyAuth);
VerificationRouter.post("/verifyEmail", verifyEmail);
VerificationRouter.post("/verifyForget", resetPassword);
VerificationRouter.post("/verifyDeactivation", verifyDeactivation);
VerificationRouter.post("/verifyActivation", verifyActivation);
// takes type: 'enable' to enable or nothing for disable
VerificationRouter.post("/verify2FA", verify2FA);
