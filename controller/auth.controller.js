import { z } from "zod";
import { User } from "../models/userModel.js";
import bcrypt from "bcrypt";
import { generateCookies } from "../lib/generateCookies/index.js";
import crypto from 'crypto'

export const signup = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.json({
        success: false,
        message: "Please provide required feilds",
      });
    }

    const userData = z.object({
      email: z.email("Please provide a valid email"),
      password: z.string().min(6, "Password must me atleast 6 digit long"),
    });

    const result = userData.safeParse({ email: email, password: password });

    if (!result.success) {
      return res.json({
        success: false,
        message: result.error.issues.map((i) => i.message).join(", "),
      });
    }
    const isUser = await User.findOne({ email: result.data.email });

    if (isUser)
      return res.json({ success: false, message: "User already exists!" });
    // pass and verfication tokens
    const hashedPassword = await bcrypt.hash(result.data.password, 10);
   const verificationToken = crypto.randomInt(100000, 1000000);

    // saving user
    const name = result.data.email.split("@")[0];
    const newUser = new User({
      name: name,
      email: result.data.email,
      password: hashedPassword,
      verificationToken: verificationToken,
      verificationTokenExpiresAt: Date.now() + 3600 * 1000, // 1 hour
    });

    await newUser.save();

    // setting cookies

    await generateCookies(res, newUser._id);

    res.json({ success: true, message: "User created sucessfully!" });
  } catch (error) {
    console.log("Error while creating user!", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};

export const signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({
        success: false,
        message: "Email or password not provided!",
      });
    }
    const isUser = await User.findOne({ email: email });
    if (!isUser) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const matchPass = await bcrypt.compare(password, isUser.password);
    if (!matchPass) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    await generateCookies(res, isUser._id);
    const updateEntry = await User.findOneAndUpdate(
      { email: email },
      { $set: { lastlogin: Date.now() } },
    );

    res.status(200).json({ success: true, message: "login sucessfull!" });
  } catch (error) {
    console.log("Error while logining user: ", error.message);
    return res
      .status(400)
      .json({ success: false, message: "Somethign went wrong!" });
  }
};
