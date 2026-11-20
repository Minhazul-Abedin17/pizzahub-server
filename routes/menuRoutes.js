
import express from "express";
import { ObjectId } from "mongodb";

const router = express.Router();

// Get all approved and active menu items
router.get("/", async (req, res) => {
  const db = req.app.locals.db;

  const result = await db.collection("menuItems")
    .find({
      status: "approved",
      isActive: true
    })
    .toArray();

  res.json(result);
});

// Get featured menu items
router.get("/featured", async (req, res) => {
  const db = req.app.locals.db;

  const result = await db.collection("menuItems")
    .find({
      status: "approved",
      isActive: true,
      isFeatured: true
    })
    .limit(6)
    .toArray();

  res.json(result);
});

// Get single menu item by ID
router.get("/:id", async (req, res) => {
  const db = req.app.locals.db;
  const id = req.params.id;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid item ID" });
  }

  const result = await db.collection("menuItems").findOne({
    _id: new ObjectId(id),
    status: "approved",
    isActive: true
  });

  res.json(result);
});

export default router;
