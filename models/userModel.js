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
    trim: true,
    lowercase: true,
  },

  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },

  isVerified: {
    type: Boolean,
    default: false,
  },
  verificationToken: Number,
  verificationTokenExpiresAt: Date,
  passwordResetToken: String,
  passwordResetTokenExpiresAt: Date,
  lastlogin: {
    type: Date,
    default: Date.now,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  twofa: {
    type: Boolean,
    default: false,
  },
  twofaEnableToken: Number,
  twofaEnableTokenExpiresAt: Date,
  twofaDisableToken: Number,
  twofaDisableExpiresAt: Date,
  deactivationCode: Number,
  deactivationCodeExpiresAt: Date,
  activationCode: Number,
  activationCodeExpiresAt: Date,
  twofaSignInToken: Number,
  twofaSignInTokenExpiresAt: Date,
});

export const User = model("User", userSchema);
