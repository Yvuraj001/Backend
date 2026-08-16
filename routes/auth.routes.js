import express from "express";
import { signup , signin} from "../controller/auth.controller.js";

export const router = express.Router();


router.post("/signup", signup);

router.post("/signin", signin);
router.post("/logout", (req, res) => {});
router.post("/forgot-user", (req, res) => {});
router.delete("/delete-user", (req, res) => {});
