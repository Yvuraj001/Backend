import express from "express";
import { signup, signin, logout } from "../controller/auth.controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";

export const authRouter = express.Router();

authRouter.post("/signup", signup);
authRouter.post("/signin", verifyAuth, signin);
authRouter.post("/logout", logout);
