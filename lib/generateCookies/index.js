import jwt from "jsonwebtoken";

export const generateCookies = (res, userId) => {

  const useCrossSiteCookie = process.env.COOKIE_SAME_SITE === "none";
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "28d",
  });

  res.cookie("pass", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production" || useCrossSiteCookie,
    sameSite: useCrossSiteCookie ? "none" : "strict",
    maxAge: 28 * 24 * 60 * 60 * 1000,
  });
  return token;
};
