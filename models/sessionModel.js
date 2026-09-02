import { Schema, model } from "mongoose";

const sessionSchema = new Schema({
  userId: { type: String, required: true },
  accessToken: {type: String, required:true },
  refreshToken: {type: String, required: true},
  isValid: { type: Boolean, default: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
});

export const Session = model("Session", sessionSchema);
