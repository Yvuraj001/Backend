import jwt from "jsonwebtoken";

export const verifyAuth = async (req, res, next) => {
  try {
    const cookie = await req.cookies.pass;
    const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);
    if (tokenMatched.userId) {
      return res.json({
        success: true,
        userId: tokenMatched.userId,
        message: "You are already logged in!",
      });
    }
  } catch (error) {
    console.log("the error in verifyAuth or not logged in", error.message);

    return next();
  }
};
