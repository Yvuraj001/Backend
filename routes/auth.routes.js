import express from "express";
import {
  signup,
  signin,
  logout,
  deactivateMe,
  activateMe,
  forgotMe,
  verifyEmail,
  resetPassword,
} from "../controller/auth.controller.js";

export const router = express.Router();

router.post("/signup", signup);
router.post("/signin", signin);
router.post("/logout", logout);
router.post("/forgot-user",forgotMe);
router.post("/deactivate-user", deactivateMe);
router.post("/activate", activateMe);
router.post("/verify", verifyEmail)
router.post("/changePass", resetPassword);
