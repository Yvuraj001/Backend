import express from "express";
import rateLimit from "express-rate-limit";
import {
  logout,
  signin,
  signup,
  logout_all,
} from "../controller/auth.controller.js";
import { refresh } from "../controller/refresh.controller.js";
import { upload_response } from "../controller/upload.controller.js";
import { upload_avatar } from "../lib/multer/upload_avatar.js";
import { upload } from "../lib/multer/multerConfig.js";
import {
  verifyAuth,
  requireAuth,
} from "../lib/verifyAuthentication/verifyAuth.js";
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRouter = express.Router();

authRouter.post("/signup", limiter, verifyAuth, signup);
authRouter.post("/signin", limiter, signin);
authRouter.post("/refresh", limiter, refresh);
authRouter.get("/logout", logout);
authRouter.get("/logout-all", logout_all);
authRouter.post(
  "/upload/avatar",
  limiter,
  requireAuth,
  upload_avatar,
  upload_response,
);
