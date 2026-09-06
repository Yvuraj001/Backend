import { User } from "../models/userModel.js";

export const upload_response = async (req, res) => {
  try {
    const userId = req.userId;
    const file = req.file
    console.log("the file from user is :", file)
    const isUser = await User.findOne({ _id: userId });
      
    res
      .status(200)
      .json({ success: true, message: "Avatar uploaded successfully!" });
  } catch (error) {
    console.log("Error while uploading user avatar!", error.message);
    res
      .status(500)
      .json({ success: false, message: "Failed to upload avatar!" });
  }
};
