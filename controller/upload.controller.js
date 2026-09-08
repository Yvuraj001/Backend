import { User } from "../models/userModel.js";
import cloudinary from "../utils/cloudinary.config.js";
import fs from "fs/promises";

export const upload_response = async (req, res) => {
  try {
    const userId = req.userId;
    if (!req.file)
      return res
        .status(400)
        .json({ success: false, message: "No file uploaded!" });

    const isUser = await User.findById(userId);

    if (!isUser) {
      fs.unlink(req.file.path).catch(() => {});
      return res
        .status(404)
        .json({ success: false, message: "User not found!" });
    }
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "avatars",
      public_id: userId,
      overwrite: true,
      invalidate: true,
      transformation: [
        { width: 300, height: 300, crop: "fill", gravity: "face" },
      ],
    });

    if (result.secure_url) {
      isUser.userAvatar = result.secure_url;
      await isUser.save();
      fs.unlink(req.file.path).catch(() => {});

      return res.status(200).json({
        success: true,
        message: "Avatar uploaded successfully!",
        url: result.secure_url,
      });
    }

    return res
      .status(500)
      .json({ success: false, message: "Failed to upload avatar!" });
  } catch (error) {
    console.log("Error while uploading user avatar!", error.message);
    fs.unlink(req.file.path).catch(() => {});
    return res
      .status(500)
      .json({ success: false, message: "Failed to upload avatar!" });
  }
};
