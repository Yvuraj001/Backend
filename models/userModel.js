import { Schema, model } from "mongoose";

const userSchema = Schema({
  name: {
    type: String,
    default: "Not Specified",
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },

  password: {
    type: String,
    required: true,
  },
  createAt: {
    type: Date,
    default: Date.now,
  },

  isVerified: {
    type: Boolean,
    default: false,
  },
  verificationToken: Number,
  verificationTokenExpiresAt: Date,
  passwordResetToken: Number,
  passwordResetTokenExpiresAt: Date,
  lastlogin: {
    type: Date,
    default: Date.now,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  twofa:{
    type: Boolean,
    default: false
  },
  twofaToken: Number, 
  twofaTokenExpiresAt: Date
});

export const User = model("User", userSchema);
