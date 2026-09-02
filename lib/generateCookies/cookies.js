import jwt from "jsonwebtoken";
import { Session } from "../../models/sessionModel.js";
import crypto from "crypto";
const isCrossSite = process.env.COOKIE_SAME_SITE === "none";
export const cookiesOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production" || isCrossSite,
  sameSite: isCrossSite ? "none" : "strict",
};
export const generateCookies = async (res, userId, req) => {
  const accessAge = 15 * 60 * 1000;
  const refreshAge = 30 * 24 * 60 * 60 * 1000;

  const accessToken = await jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: Date.now() + 15 * 60 * 1000,
  });
  const refreshToken = await jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "28d",
  });

  const session = new Session({
    userId,
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: Date.now() + 15 * 60 * 1000,
  });
  await session.save();

  res.cookie("pass", refreshToken, { ...cookiesOptions, maxAge: refreshAge });
  res.cookie("ref", accessToken, { ...cookiesOptions, maxAge: accessAge });

};
