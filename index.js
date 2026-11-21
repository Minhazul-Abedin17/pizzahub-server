
import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import cors from "cors";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 8000;

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

app.use(express.json());

// MongoDB connection
const client = new MongoClient(process.env.MONGODB_URI);

await client.connect();

console.log("MongoDB connected successfully!");

const db = client.db(process.env.DB_NAME);
const menuCollection = db.collection("menuItems");

// Better Auth JWT
const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
);

// Verify login token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Please login first",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.CLIENT_URL,
      audience: process.env.CLIENT_URL,
    });

    req.user = {
      id: payload.id,
      email: payload.email,
      role: payload.role,
    };

    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);

    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};

// Check user role
const verifyRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({
        message: "You do not have permission",
      });
    }

    next();
  };
};

// Search helper
const escapeRegex = (value) => {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

// Home
app.get("/", (req, res) => {
  res.send("PizzaHub Server is Running!");
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is healthy",
  });
});

// Logged-in user
app.get("/api/me", verifyToken, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});

// Customer test
app.get(
  "/api/customer-test",
  verifyToken,
  verifyRole("customer"),
  (req, res) => {
    res.json({
      message: "Customer access successful",
      user: req.user,
    });
  }
);

// Vendor test
app.get(
  "/api/vendor-test",
  verifyToken,
  verifyRole("vendor"),
  (req, res) => {
    res.json({
      message: "Vendor access successful",
      user: req.user,
    });
  }
);

// Admin test
app.get(
  "/api/admin-test",
  verifyToken,
  verifyRole("admin"),
  (req, res) => {
    res.json({
      message: "Admin access successful",
      user: req.user,
    });
  }
);

// Get approved menu items
app.get("/api/menu-items", async (req, res) => {
  try {
    const { search, category, location, sort } = req.query;

    const filter = {
      status: "approved",
      isActive: true,
    };

    if (typeof search === "string" && search.trim()) {
      filter.name = {
        $regex: escapeRegex(search.trim()),
        $options: "i",
      };
    }

    if (typeof category === "string" && category !== "All") {
      filter.category = category;
    }

    if (typeof location === "string" && location.trim()) {
      filter.location = {
        $regex: escapeRegex(location.trim()),
        $options: "i",
      };
    }

    let sortOption = {};

    if (sort === "low-to-high") {
      sortOption = { price: 1 };
    } else if (sort === "high-to-low") {
      sortOption = { price: -1 };
    }

    const result = await menuCollection
      .find(filter)
      .sort(sortOption)
      .toArray();

    res.json(result);
  } catch (error) {
    console.error("Get menu error:", error);

    res.status(500).json({
      message: "Failed to load menu items",
    });
  }
});

// Get categories
app.get("/api/menu-items/categories", async (req, res) => {
  try {
    const result = await menuCollection.distinct("category", {
      status: "approved",
      isActive: true,
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({
      message: "Failed to load categories",
    });
  }
});

// Get featured pizzas
app.get("/api/menu-items/featured", async (req, res) => {
  try {
    const result = await menuCollection
      .find({
        status: "approved",
        isActive: true,
        isFeatured: true,
      })
      .limit(6)
      .toArray();

    res.json(result);
  } catch (error) {
    res.status(500).json({
      message: "Failed to load featured pizzas",
    });
  }
});

// Vendor: Get own pizzas
app.get(
  "/api/menu-items/my-items",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const result = await menuCollection
        .find({
          vendorId: req.user.id,
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({
        message: "Failed to load your pizzas",
      });
    }
  }
);

// Vendor: Get own pizza details
app.get(
  "/api/menu-items/my-items/:id",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid pizza ID",
        });
      }

      const result = await menuCollection.findOne({
        _id: new ObjectId(id),
        vendorId: req.user.id,
      });

      if (!result) {
        return res.status(404).json({
          message: "Pizza not found",
        });
      }

      res.json(result);
    } catch (error) {
      res.status(500).json({
        message: "Failed to load pizza details",
      });
    }
  }
);

// Get one approved pizza (Public)
app.get("/api/menu-items/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        message: "Invalid pizza ID",
      });
    }

    const result = await menuCollection.findOne({
      _id: new ObjectId(id),
      status: "approved",
      isActive: true,
    });

    if (!result) {
      return res.status(404).json({
        message: "Pizza not found",
      });
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({
      message: "Failed to load pizza",
    });
  }
});

// Vendor: Add pizza
app.post(
  "/api/menu-items",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        price,
        image,
        category,
        location,
      } = req.body;

      const validFields = [
        name,
        description,
        image,
        category,
        location,
      ].every(
        (value) => typeof value === "string" && value.trim()
      );

      let validImage = false;

      if (typeof image === "string") {
        try {
          validImage = new URL(image).protocol === "https:";
        } catch {
          validImage = false;
        }
      }

      if (
        !validFields ||
        !validImage ||
        !Number.isFinite(Number(price)) ||
        Number(price) <= 0
      ) {
        return res.status(400).json({
          message: "Please provide valid pizza information",
        });
      }

      const activeItems = await menuCollection.countDocuments({
        vendorId: req.user.id,
        isActive: true,
      });

      if (activeItems >= 3) {
        return res.status(403).json({
          message: "Free plan allows only 3 active pizzas",
        });
      }

      const newItem = {
        name: name.trim(),
        description: description.trim(),
        price: Number(price),
        image: image.trim(),
        category: category.trim(),
        location: location.trim(),
        vendorId: req.user.id,
        status: "pending",
        isActive: true,
        isFeatured: false,
        createdAt: new Date(),
      };

      const result = await menuCollection.insertOne(newItem);

      res.status(201).json({
        success: true,
        message: "Pizza submitted for approval",
        item: {
          ...newItem,
          _id: result.insertedId,
        },
      });
    } catch (error) {
      console.error("Add pizza error:", error);

      res.status(500).json({
        message: "Failed to add pizza",
      });
    }
  }
);

// Vendor: Edit own pizza
app.patch(
  "/api/menu-items/:id",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          message: "Invalid pizza ID",
        });
      }

      const {
        name,
        description,
        price,
        image,
        category,
        location,
      } = req.body;

      const validFields = [
        name,
        description,
        image,
        category,
        location,
      ].every(
        (value) => typeof value === "string" && value.trim()
      );

      let validImage = false;

      if (typeof image === "string") {
        try {
          validImage = new URL(image).protocol === "https:";
        } catch {
          validImage = false;
        }
      }

      if (
        !validFields ||
        !validImage ||
        !Number.isFinite(Number(price)) ||
        Number(price) <= 0
      ) {
        return res.status(400).json({
          message: "Please provide valid pizza information",
        });
      }

      const updatedData = {
        name: name.trim(),
        description: description.trim(),
        price: Number(price),
        image: image.trim(),
        category: category.trim(),
        location: location.trim(),
        status: "pending",
        updatedAt: new Date(),
      };

      const result = await menuCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user.id,
        },
        {
          $set: updatedData,
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          message: "Pizza not found",
        });
      }

      res.json({
        success: true,
        message: "Pizza updated and sent for approval again",
      });
    } catch (error) {
      console.error("Update pizza error:", error);

      res.status(500).json({
        message: "Failed to update pizza",
      });
    }
  }
);

app.listen(PORT, () => {
  console.log(`PizzaHub server is running at ${PORT}`);
});
