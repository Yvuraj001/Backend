import jwt from "jsonwebtoken";

export const verifyAuth = async (req, res,  type) => {

  try {
    const cookie = await req.cookies.pass;
    
    const tokenMatched = await jwt.verify(cookie, process.env.JWT_SECRET);
    if (type) {
      if (tokenMatched.userId) {
        return res.json({
          userId: tokenMatched.userId,
          message: "You are already logged in!",
        });
      }
    }
    return {
      success: true,
      userId: tokenMatched.userId,
      message: "valid token!",
    };
  } catch (error) {
    console.log("the error in verifyAuth or not logged in", error.message);
    
    return null;
  }
};
