import cookieParser from "cookie-parser";
import express from "express";
import connectDB from "./lib/db/index.js";
import "dotenv/config";
import { authRouter } from "./routes/auth.routes.js";
import { securityRoutes } from "./routes/security.routes.js";
import { VerificationRouter } from "./routes/verification.routes.js";
import rateLimit from "express-rate-limit";
import cors from "cors";
const app = express();
const port = process.env.PORT;
await connectDB();

app.use(cookieParser());
app.use(express.json());
// app.use(
//   cors({
//     cors: {
//       origin: "http://localhost:5173",

//       credentials: true,

//       methods: ["GET", "POST"],
//     },
//   }),
// );
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/auth", authRouter);
app.use("/api/auth/security", securityRoutes);
app.use("/api/auth/verification", VerificationRouter);

app.get("/health",limiter,  (req, res) => {
  res
    .status(200)
    .json({ health: "OK", message: "Everything running beautifully!!" });
});
app.listen(port, async () => {
  console.log("server running");
});
