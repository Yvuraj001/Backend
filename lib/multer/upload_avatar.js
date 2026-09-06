import multer from "multer";
import { upload } from "./multerConfig.js";

export const upload_avatar = (req, res, next) => {
  upload.single("avatar")(req, res, (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ success: false, message: err.message });
    } else if (err) {
      console.error("Upload error:", err.message);
      return res
        .status(400)
        .json({ success: false, message: "Only images are allowed!" });
    }
    next();
  });
};
