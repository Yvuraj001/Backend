import express from "express";
import { signup, signin, logout } from "../controller/auth.controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";
import rateLimit from "express-rate-limit";

const limiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
  });

export const authRouter = express.Router();

authRouter.post("/signup", limiter, signup);
authRouter.post("/signin", limiter, verifyAuth, signin);
authRouter.post("/logout", logout);
