import mongoose, { connect } from "mongoose";

const connectDB = async () => {
  try {
    const conn = await connect(
      process.env.MONGODB_URI || "mongodb://localhost:27017",
    );

    console.log("DB connected!");
  } catch (error) {
    console.log("Failed to connect to DB: ", error.message);
  }
};

export default connectDB;
