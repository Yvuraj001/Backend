import express from "express";
import { logout, signin, signup } from "../controller/auth.controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";
import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

export const authRouter = express.Router();

authRouter.post("/signup", limiter, verifyAuth, signup);
authRouter.post("/signin", limiter, signin);
authRouter.get("/logout", logout);
