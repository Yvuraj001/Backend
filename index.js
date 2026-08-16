import express from "express";
import connectDB from "./lib/db/index.js";
import "dotenv/config";
import { router } from "./routes/auth.routes.js";

const app = express();
const port = 3000;
await connectDB();

app.use(express.json());
app.use("/api/auth", router);

app.listen(port, async () => {
  console.log("server running");
});
