import crypto from "crypto";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from 'fs/promises'

// directory to this file: e.g : /Users/me/Codes/Backend/lib/multer
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// required directory: e.g. : /Users/me/Codes/Backend/public/temp
const joinedPath = path.join(__dirname, "../../public/temp");

// checking directory exists or not

await fs.mkdir(joinedPath, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, joinedPath);
  },
  filename: (req, file, cb) => {
    const randomHex = crypto.randomBytes(16).toString("hex");
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${randomHex}${ext}`);
  },
});

export const upload = multer({
  storage: storage,
 
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
  limits: {
    fileSize: 2 * 1024 * 1024, // 2mb
  },
});
