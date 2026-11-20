
import express from "express";
import {
  verifyToken,
  verifyRole,
} from "../middleware/verifyToken.js";

const router = express.Router();

// Any logged-in user
router.get("/me", verifyToken, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});

// Customer only
router.get(
  "/customer-test",
  verifyToken,
  verifyRole("customer"),
  (req, res) => {
    res.json({
      message: "Customer access successful",
      user: req.user,
    });
  }
);

// Vendor only
router.get(
  "/vendor-test",
  verifyToken,
  verifyRole("vendor"),
  (req, res) => {
    res.json({
      message: "Vendor access successful",
      user: req.user,
    });
  }
);

// Admin only
router.get(
  "/admin-test",
  verifyToken,
  verifyRole("admin"),
  (req, res) => {
    res.json({
      message: "Admin access successful",
      user: req.user,
    });
  }
);

export default router;
