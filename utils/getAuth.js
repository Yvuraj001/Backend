import jwt from 'jsonwebtoken'
import { Session } from '../models/sessionModel.js';

export const get_auth = async (req, res) => {
  try {
    const accessCookie = await req.cookies.ref;
    const tokenMatched = await jwt.verify(accessCookie, process.env.JWT_SECRET);
    if (tokenMatched.userId) {
      return res.status(200).json({
        success: true,
        userId: tokenMatched.userId,
        message: "You arelogged in!",
      });
    }

  } catch (error) {
    console.log("(ignore)-access token not valid.", error.message);
  }

  try {
    const refreshCookie = req.cookies.pass;
    const match = await jwt.verify(
      refreshCookie,
      process.env.JWT_REFRESH_SECRET,
    );

    const session = await Session.findOne({
      userId: match.userId,
      refreshToken: refreshCookie,
      isValid: true,
      expiresAt: { $gt: Date.now() },
    });
    
    if (session) {
      return res.status(200).json({
        success: true,
        userId: match.userId,
        message: "You already logged in!",
      });
    }
    return res.status(401).json({
      success: false,
      message: "You are not logged in!",
    })
  } catch (error) {
    console.log("(ignore)-Both cookies are absent", error.message);
    return res.status(401).json({
      success: false,
      message: "You are not logged in!",
    });
  }
};
