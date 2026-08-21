import express from "express";
import connectDB from "./lib/db/index.js";
import "dotenv/config";
import { authRouter } from "./routes/auth.routes.js";
import { securityRoutes } from "./routes/security.routes.js";
import { VerificationRouter } from "./routes/verification.routes.js";

const app = express();
const port = process.env.PORT
await connectDB();

app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/auth/security", securityRoutes)
app.use("/api/auth/verification", VerificationRouter)

app.listen(port, async () => {
  console.log("server running");
  
});
