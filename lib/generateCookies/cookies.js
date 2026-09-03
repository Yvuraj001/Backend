import jwt from "jsonwebtoken";
import { Session } from "../../models/sessionModel.js";

export const isCrossSite = process.env.COOKIE_SAME_SITE === "none";
export const cookiesOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production" || isCrossSite,
  sameSite: isCrossSite ? "none" : "strict",
};

export const generateCookies = async (res, userId, req) => {
  const accessAge = 15 * 60 * 1000;
  const refreshAge = 28 * 24 * 60 * 60 * 1000;

  const accessToken = await jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = await jwt.sign(
    { userId },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: "28d",
    },
  );

  const session = new Session({
    userId,
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: new Date(Date.now() + refreshAge),
  });
  await session.save();

  res.cookie("pass", refreshToken, { ...cookiesOptions, maxAge: refreshAge });
  res.cookie("ref", accessToken, { ...cookiesOptions, maxAge: accessAge });
};
