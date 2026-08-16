import jwt from "jsonwebtoken";

export const generateCookies = (res, userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET);
  res.cookie("pass", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    
  });
  return token;
};
