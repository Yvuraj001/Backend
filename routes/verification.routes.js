import express from "express";
import {
  verifyEmail,
  resetPassword,
  verifyActivation,
  verifyDeactivation,
  verify2FA,
} from "../controller/controller.js";
import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";

export const VerificationRouter = express.Router();

// verifies crossponding routes after their initalisation from security.routes.js
VerificationRouter.get("/verify", async (req, res) => {
  try {
    const cookie = await req.cookies.pass;
    const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);
    if (tokenMatched.userId) {
      return res.json({
        success: true,
        userId: tokenMatched.userId,
        message: "You arelogged in!",
      });
    }
  } catch (error) {
    console.log("the error in verifyAuth or not logged in", error.message);

    return res.json({
      success: false,
      message: "Not logged in!",
    });
  }
});
VerificationRouter.post("/verifyEmail", verifyEmail);
VerificationRouter.post("/verifyForget", resetPassword);
VerificationRouter.post("/verifyDeactivation", verifyDeactivation);
VerificationRouter.post("/verifyActivation", verifyActivation);
// takes type: 'enable' to enable or nothing for disable
VerificationRouter.post("/verify2FA", verify2FA);
