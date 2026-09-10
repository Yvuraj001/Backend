import cookieParser from "cookie-parser";
import express from "express";
import connectDB from "./lib/db/index.js";
import "dotenv/config";
import { authRouter } from "./routes/auth.routes.js";
import { securityRoutes } from "./routes/security.routes.js";
import { VerificationRouter } from "./routes/verification.routes.js";
import { oAuthRoutes } from "./routes/oAuth.routes.js";
import rateLimit from "express-rate-limit";
import cors from "cors";
import session from "express-session"; 

const app = express();
const port = process.env.PORT;


const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
await connectDB();

app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin(origin, callback) {
     
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin is not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST"],
  }),
);
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
    },
  }),
);
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/auth", authRouter);
app.use("/api/auth/security", securityRoutes);
app.use("/api/auth/verification", VerificationRouter);
app.use("/api/auth/oAuth/google", oAuthRoutes)
app.get("/health",limiter,  (req, res) => {
  res
    .status(200)
    .json({ health: "OK", message: "Everything running beautifully!!" });
});
app.listen(port, async () => {
  console.log("server running");
});
