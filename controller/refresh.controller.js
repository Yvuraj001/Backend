import { verifyAuth } from "../lib/verifyAuthentication/verifyAuth.js";

export const refresh = async (req, res) => {
  // refreshes the access token for frontend purpose
  await verifyAuth(req, res, () => {
    return res.status(401).json({
      success: false,
      message: "You are not logged in (outside) !",
    });
  });
};
