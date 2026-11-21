import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import cors from "cors";
import Stripe from "stripe";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 8000;
const CLIENT_URL = process.env.CLIENT_URL;
const client = new MongoClient(process.env.MONGODB_URI);
await client.connect();

console.log("MongoDB connected successfully!");

const db = client.db(process.env.DB_NAME);
const menuCollection = db.collection("menuItems");
const usersCollection = db.collection("user");
const ordersCollection = db.collection("orders");
const transactionsCollection = db.collection("transactions");

const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
  }),
);

// Better Auth JWT
const JWKS = createRemoteJWKSet(new URL(`${CLIENT_URL}/api/auth/jwks`));

// --------------------------------------------------
// STRIPE WEBHOOK
// Must be before express.json()
// --------------------------------------------------

app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) {
      return res.status(503).send("Stripe is not configured");
    }

    const signature = req.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (error) {
      console.error("Stripe webhook verification failed:", error.message);
      return res.status(400).send("Invalid webhook signature");
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;

        if (session.mode === "subscription" && session.metadata?.vendorEmail) {
          const subscriptionId = session.subscription;

          await usersCollection.updateOne(
            { email: session.metadata.vendorEmail },
            {
              $set: {
                subscriptionPlan: "premium",
                subscriptionStatus: "active",
                stripeSubscriptionId: subscriptionId,
                subscriptionUpdatedAt: new Date(),
              },
            },
          );
        }
      }

      if (
        event.type === "customer.subscription.updated" ||
        event.type === "customer.subscription.deleted"
      ) {
        const subscription = event.data.object;

        const vendorEmail = subscription.metadata?.vendorEmail;

        if (vendorEmail) {
          const isActive =
            subscription.status === "active" ||
            subscription.status === "trialing";

          await usersCollection.updateOne(
            { email: vendorEmail },
            {
              $set: {
                subscriptionPlan: isActive ? "premium" : "free",
                subscriptionStatus: subscription.status,
                subscriptionUpdatedAt: new Date(),
              },
            },
          );
        }
      }

      if (event.type === "invoice.paid") {
        const invoice = event.data.object;

        const subscriptionId =
          typeof invoice.subscription === "string"
            ? invoice.subscription
            : invoice.subscription?.id;

        if (subscriptionId) {
          const user = await usersCollection.findOne({
            stripeSubscriptionId: subscriptionId,
          });

          if (user) {
            const alreadyExists = await transactionsCollection.findOne({
              stripeEventId: event.id,
            });

            if (!alreadyExists) {
              await transactionsCollection.insertOne({
                stripeEventId: event.id,
                vendorEmail: user.email,
                vendorName: user.name || "",
                amount: invoice.amount_paid / 100,
                currency: invoice.currency,
                type: "subscription",
                status: "paid",
                stripeInvoiceId: invoice.id,
                createdAt: new Date(),
              });
            }
          }
        }
      }

      res.json({ received: true });
    } catch (error) {
      console.error("Webhook processing error:", error);
      res.status(500).send("Webhook processing failed");
    }
  },
);

app.use(express.json());

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Please login first",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: CLIENT_URL,
      audience: CLIENT_URL,
    });

    if (!payload.id || !payload.email) {
      return res.status(401).json({
        message: "Invalid user token",
      });
    }

    // Get current user from database.
    // This makes blocking and role changes effective
    // without depending only on an old JWT.
    const dbUser = await usersCollection.findOne({
      email: payload.email,
    });

    if (!dbUser) {
      return res.status(401).json({
        message: "User account not found",
      });
    }

    if (dbUser.isBlocked === true || dbUser.status === "blocked") {
      return res.status(403).json({
        message: "Your account has been blocked",
      });
    }

    req.user = {
      id: payload.id,
      email: payload.email,
      name: dbUser.name || payload.name || "",
      role: dbUser.role || payload.role,
    };

    next();
  } catch (error) {
    console.error("Token verification failed:", error.message);

    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};

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

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const validObjectId = (id) => ObjectId.isValid(id);
const getUserIdFilter = (id) => {
  const conditions = [{ _id: id }, { id }];

  if (validObjectId(id)) {
    conditions.push({ _id: new ObjectId(id) });
  }

  return { $or: conditions };
};

const getVendorPlan = async (email) => {
  const user = await usersCollection.findOne({ email });

  if (
    user?.subscriptionPlan === "premium" &&
    user?.subscriptionStatus === "active"
  ) {
    return "premium";
  }

  return "free";
};

// --------------------------------------------------
// HOME AND HEALTH
// --------------------------------------------------

app.get("/", (req, res) => {
  res.send("PizzaHub Server is Running!");
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is healthy",
  });
});

// --------------------------------------------------
// AUTH TEST ROUTES
// --------------------------------------------------

app.get("/api/me", verifyToken, (req, res) => {
  res.json({
    success: true,
    user: req.user,
  });
});

app.get(
  "/api/customer-test",
  verifyToken,
  verifyRole("customer"),
  (req, res) => {
    res.json({ message: "Customer access successful", user: req.user });
  },
);

app.get("/api/vendor-test", verifyToken, verifyRole("vendor"), (req, res) => {
  res.json({ message: "Vendor access successful", user: req.user });
});

app.get("/api/admin-test", verifyToken, verifyRole("admin"), (req, res) => {
  res.json({ message: "Admin access successful", user: req.user });
});

// --------------------------------------------------
// PUBLIC MENU API
// --------------------------------------------------

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

    const result = await menuCollection.find(filter).sort(sortOption).toArray();

    res.json(result);
  } catch (error) {
    console.error("Get menu error:", error);
    res.status(500).json({ message: "Failed to load menu items" });
  }
});

// Categories
app.get("/api/menu-items/categories", async (req, res) => {
  try {
    const result = await menuCollection.distinct("category", {
      status: "approved",
      isActive: true,
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ message: "Failed to load categories" });
  }
});

// Featured pizzas
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
    res.status(500).json({ message: "Failed to load featured pizzas" });
  }
});



// --------------------------------------------------
// VENDOR MENU API
// --------------------------------------------------

// Get own pizzas
app.get(
  "/api/menu-items/my-items",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const result = await menuCollection
        .find({ vendorId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load your pizzas" });
    }
  },
);

// Get own pizza details
app.get(
  "/api/menu-items/my-items/:id",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid pizza ID" });
      }

      const result = await menuCollection.findOne({
        _id: new ObjectId(id),
        vendorId: req.user.id,
      });

      if (!result) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load pizza details" });
    }
  },
);

// Public pizza details
app.get("/api/menu-items/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!validObjectId(id)) {
      return res.status(400).json({ message: "Invalid pizza ID" });
    }

    const result = await menuCollection.findOne({
      _id: new ObjectId(id),
      status: "approved",
      isActive: true,
    });

    if (!result) {
      return res.status(404).json({ message: "Pizza not found" });
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ message: "Failed to load pizza" });
  }
});
// Add pizza
app.post(
  "/api/menu-items",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { name, description, price, image, category, location } = req.body;

      const validFields = [name, description, image, category, location].every(
        (value) => typeof value === "string" && value.trim(),
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

      const plan = await getVendorPlan(req.user.email);

      const activeItems = await menuCollection.countDocuments({
        vendorId: req.user.id,
        isActive: true,
      });

      if (plan === "free" && activeItems >= 3) {
        return res.status(403).json({
          message:
            "Free plan allows only 3 active pizzas. Upgrade to Premium for unlimited listings.",
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
      res.status(500).json({ message: "Failed to add pizza" });
    }
  },
);

// Edit own pizza
app.patch(
  "/api/menu-items/:id",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid pizza ID" });
      }

      const { name, description, price, image, category, location } = req.body;

      const validFields = [name, description, image, category, location].every(
        (value) => typeof value === "string" && value.trim(),
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

      const result = await menuCollection.updateOne(
        {
          _id: new ObjectId(id),
          vendorId: req.user.id,
        },
        {
          $set: {
            name: name.trim(),
            description: description.trim(),
            price: Number(price),
            image: image.trim(),
            category: category.trim(),
            location: location.trim(),
            status: "pending",
            updatedAt: new Date(),
          },
        },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json({
        success: true,
        message: "Pizza updated and sent for approval again",
      });
    } catch (error) {
      console.error("Update pizza error:", error);
      res.status(500).json({ message: "Failed to update pizza" });
    }
  },
);

// Vendor: Delete own pizza

app.delete(
  "/api/menu-items/:id",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid pizza ID" });
      }

      const result = await menuCollection.deleteOne({
        _id: new ObjectId(id),
        vendorId: req.user.id,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json({
        success: true,
        message: "Pizza deleted successfully",
      });
    } catch (error) {
      console.error("Delete pizza error:", error);
      res.status(500).json({ message: "Failed to delete pizza" });
    }
  }
);

// Vendor: Update own pizza availability

app.patch(
  "/api/menu-items/:id/active",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;

      if (!validObjectId(id) || typeof isActive !== "boolean") {
        return res.status(400).json({ message: "Invalid request" });
      }

      const filter = {
        _id: new ObjectId(id),
        vendorId: req.user.id,
      };

      const item = await menuCollection.findOne(filter);

      if (!item) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      if (isActive && item.status !== "approved") {
        return res.status(400).json({
          message: "Only approved pizzas can be activated",
        });
      }

      if (isActive) {
        const plan = await getVendorPlan(req.user.email);

        const activeItems = await menuCollection.countDocuments({
          vendorId: req.user.id,
          isActive: true,
        });

        if (plan === "free" && activeItems >= 3 && !item.isActive) {
          return res.status(403).json({
            message: "Free plan allows only 3 active pizzas. Upgrade to Premium for unlimited listings.",
          });
        }
      }

      await menuCollection.updateOne(filter, {
        $set: {
          isActive,
          updatedAt: new Date(),
        },
      });

      res.json({
        success: true,
        message: `Pizza ${isActive ? "activated" : "deactivated"} successfully`,
      });
    } catch (error) {
      console.error("Update pizza availability error:", error);
      res.status(500).json({
        message: "Failed to update pizza availability",
      });
    }
  }
);
// --------------------------------------------------
// CUSTOMER ORDER API
// --------------------------------------------------

// Create order
app.post(
  "/api/orders",
  verifyToken,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const {
        menuItemId,
        deliveryDate,
        deliveryAddress,
        message = "",
        quantity = 1,
      } = req.body;

      if (
        !validObjectId(menuItemId) ||
        typeof deliveryAddress !== "string" ||
        !deliveryAddress.trim() ||
        typeof deliveryDate !== "string" ||
        !Number.isInteger(Number(quantity)) ||
        Number(quantity) < 1 ||
        Number(quantity) > 20
      ) {
        return res.status(400).json({
          message: "Please provide valid order information",
        });
      }

      const date = new Date(deliveryDate);

      if (
        Number.isNaN(date.getTime()) ||
        date < new Date(new Date().setHours(0, 0, 0, 0))
      ) {
        return res.status(400).json({
          message: "Please select a valid future delivery date",
        });
      }

      const item = await menuCollection.findOne({
        _id: new ObjectId(menuItemId),
        status: "approved",
        isActive: true,
      });

      if (!item) {
        return res.status(404).json({
          message: "This pizza is not available for ordering",
        });
      }

      if (item.vendorId === req.user.id) {
        return res.status(403).json({
          message: "You cannot order your own pizza",
        });
      }

      const existingOrder = await ordersCollection.findOne({
        customerId: req.user.id,
        menuItemId,
        deliveryDate: {
          $gte: new Date(date.setHours(0, 0, 0, 0)),
          $lt: new Date(date.setHours(23, 59, 59, 999)),
        },
        status: { $in: ["pending", "accepted"] },
      });

      if (existingOrder) {
        return res.status(409).json({
          message:
            "You already have an active order for this pizza on this date",
        });
      }

      const totalPrice = item.price * Number(quantity);

      const order = {
        menuItemId,
        itemName: item.name,
        itemImage: item.image,
        unitPrice: item.price,
        quantity: Number(quantity),
        totalPrice,
        vendorId: item.vendorId,
        customerId: req.user.id,
        customerEmail: req.user.email,
        customerName: req.user.name,
        vendorEmail: "",
        deliveryDate: new Date(deliveryDate),
        deliveryAddress: deliveryAddress.trim(),
        message: typeof message === "string" ? message.trim() : "",
        status: "pending",
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const vendor = await usersCollection.findOne({
        $or: [{ _id: item.vendorId }, { id: item.vendorId }],
      });

      order.vendorEmail = vendor?.email || "";

      const result = await ordersCollection.insertOne(order);

      res.status(201).json({
        success: true,
        message: "Your order has been placed successfully",
        order: {
          ...order,
          _id: result.insertedId,
        },
      });
    } catch (error) {
      console.error("Create order error:", error);
      res.status(500).json({ message: "Failed to create order" });
    }
  },
);

// Customer: My orders
app.get(
  "/api/orders/my-orders",
  verifyToken,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const result = await ordersCollection
        .find({ customerId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load your orders" });
    }
  },
);

// Customer: Order details
app.get(
  "/api/orders/:id",
  verifyToken,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid order ID" });
      }

      const order = await ordersCollection.findOne({
        _id: new ObjectId(id),
        customerId: req.user.id,
      });

      if (!order) {
        return res.status(404).json({ message: "Order not found" });
      }

      res.json(order);
    } catch (error) {
      res.status(500).json({ message: "Failed to load order details" });
    }
  },
);

// Customer: Cancel pending order
app.patch(
  "/api/orders/:id/cancel",
  verifyToken,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid order ID" });
      }

      const result = await ordersCollection.updateOne(
        {
          _id: new ObjectId(id),
          customerId: req.user.id,
          status: "pending",
        },
        {
          $set: {
            status: "cancelled",
            updatedAt: new Date(),
          },
        },
      );

      if (!result.matchedCount) {
        return res.status(400).json({
          message: "Only your pending orders can be cancelled",
        });
      }

      res.json({
        success: true,
        message: "Order cancelled successfully",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to cancel order" });
    }
  },
);

// --------------------------------------------------
// VENDOR ORDER API
// --------------------------------------------------

// Vendor: Get received orders
app.get(
  "/api/vendor/orders",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const result = await ordersCollection
        .find({ vendorId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load vendor orders" });
    }
  },
);

// Vendor: Update order status
app.patch(
  "/api/vendor/orders/:id/status",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid order ID" });
      }

      if (!["accepted", "rejected", "delivered"].includes(status)) {
        return res.status(400).json({ message: "Invalid order status" });
      }

      const filter = {
        _id: new ObjectId(id),
        vendorId: req.user.id,
      };

      const order = await ordersCollection.findOne(filter);

      if (!order) {
        return res.status(404).json({ message: "Order not found" });
      }

      if (
        order.status === "pending" &&
        !["accepted", "rejected"].includes(status)
      ) {
        return res.status(400).json({
          message: "Pending orders can only be accepted or rejected",
        });
      }

      if (order.status === "accepted" && status !== "delivered") {
        return res.status(400).json({
          message: "Accepted orders can only be marked as delivered",
        });
      }

      if (order.status !== "pending" && order.status !== "accepted") {
        return res.status(400).json({
          message: "This order can no longer be updated",
        });
      }

      await ordersCollection.updateOne(filter, {
        $set: {
          status,
          updatedAt: new Date(),
        },
      });

      res.json({
        success: true,
        message: `Order ${status} successfully`,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update order" });
    }
  },
);

// --------------------------------------------------
// VENDOR SUBSCRIPTION API
// --------------------------------------------------

// Get subscription details
app.get(
  "/api/subscription/me",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      const user = await usersCollection.findOne({
        email: req.user.email,
      });

      const plan = await getVendorPlan(req.user.email);

      res.json({
        plan,
        status: user?.subscriptionStatus || "inactive",
        subscriptionUpdatedAt: user?.subscriptionUpdatedAt || null,
      });
    } catch (error) {
      res.status(500).json({
        message: "Failed to load subscription",
      });
    }
  },
);

// Create Stripe Checkout Session
app.post(
  "/api/subscription/checkout",
  verifyToken,
  verifyRole("vendor"),
  async (req, res) => {
    try {
      if (!stripe) {
        return res.status(503).json({
          message: "Stripe is not configured",
        });
      }

      if (!process.env.STRIPE_PREMIUM_PRICE_ID) {
        return res.status(503).json({
          message: "Premium subscription price is not configured",
        });
      }

      const plan = await getVendorPlan(req.user.email);

      if (plan === "premium") {
        return res.status(400).json({
          message: "You already have an active Premium subscription",
        });
      }
      const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        customer_email: req.user.email,
        line_items: [
          {
            price: process.env.STRIPE_PREMIUM_PRICE_ID,
            quantity: 1,
          },
        ],
        metadata: {
          vendorEmail: req.user.email,
          vendorId: req.user.id,
        },
        subscription_data: {
          metadata: {
            vendorEmail: req.user.email,
            vendorId: req.user.id,
          },
        },
        success_url: `${CLIENT_URL}/dashboard/vendor/subscription/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${CLIENT_URL}/dashboard/vendor/subscription/cancel`,
      });

      res.json({
        success: true,
        url: session.url,
      });
    } catch (error) {
      console.error("Stripe checkout error:", error);
      res.status(500).json({
        message: "Unable to start subscription checkout",
      });
    }
  },
);

// --------------------------------------------------
// ADMIN API
// --------------------------------------------------

// Admin dashboard statistics
app.get(
  "/api/admin/dashboard",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const [
        totalUsers,
        totalCustomers,
        totalVendors,
        blockedUsers,
        totalMenuItems,
        pendingItems,
        approvedItems,
        rejectedItems,
        totalOrders,
        pendingOrders,
        totalTransactions,
      ] = await Promise.all([
        usersCollection.countDocuments({}),
        usersCollection.countDocuments({ role: "customer" }),
        usersCollection.countDocuments({ role: "vendor" }),
        usersCollection.countDocuments({
          $or: [{ isBlocked: true }, { status: "blocked" }],
        }),
        menuCollection.countDocuments({}),
        menuCollection.countDocuments({ status: "pending" }),
        menuCollection.countDocuments({ status: "approved" }),
        menuCollection.countDocuments({ status: "rejected" }),
        ordersCollection.countDocuments({}),
        ordersCollection.countDocuments({ status: "pending" }),
        transactionsCollection.countDocuments({}),
      ]);

      res.json({
        totalUsers,
        totalCustomers,
        totalVendors,
        blockedUsers,
        totalMenuItems,
        pendingItems,
        approvedItems,
        rejectedItems,
        totalOrders,
        pendingOrders,
        totalTransactions,
      });
    } catch (error) {
      console.error("Admin dashboard error:", error);
      res.status(500).json({
        message: "Failed to load admin dashboard",
      });
    }
  },
);

// Admin: Get users
app.get(
  "/api/admin/users",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { search, role, status } = req.query;

      const filter = {};

      if (typeof role === "string" && role !== "all") {
        filter.role = role;
      }

      if (typeof search === "string" && search.trim()) {
        const regex = {
          $regex: escapeRegex(search.trim()),
          $options: "i",
        };

        filter.$or = [{ name: regex }, { email: regex }];
      }

      if (status === "blocked") {
        filter.$or = [
          ...(filter.$or || []),
          { isBlocked: true },
          { status: "blocked" },
        ];
      } else if (status === "active") {
        filter.isBlocked = { $ne: true };
        filter.status = { $ne: "blocked" };
      }

      const result = await usersCollection
        .find(filter, {
          projection: {
            name: 1,
            email: 1,
            role: 1,
            image: 1,
            isBlocked: 1,
            status: 1,
            createdAt: 1,
          },
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load users" });
    }
  },
);

// Admin: Block or unblock user
app.patch(
  "/api/admin/users/:id/status",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isBlocked } = req.body;

      if (typeof isBlocked !== "boolean") {
        return res.status(400).json({
          message: "isBlocked must be true or false",
        });
      }

      const targetUser = await usersCollection.findOne(getUserIdFilter(id));

      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }

      if (targetUser.email === req.user.email) {
        return res.status(400).json({
          message: "You cannot block your own admin account",
        });
      }

      await usersCollection.updateOne(
        { email: targetUser.email },
        {
          $set: {
            isBlocked,
            status: isBlocked ? "blocked" : "active",
            updatedAt: new Date(),
          },
        },
      );

      res.json({
        success: true,
        message: isBlocked
          ? "User blocked successfully"
          : "User unblocked successfully",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update user status" });
    }
  },
);

// Admin: Get all menu items
app.get(
  "/api/admin/menu-items",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { status, search } = req.query;

      const filter = {};

      if (
        typeof status === "string" &&
        ["pending", "approved", "rejected"].includes(status)
      ) {
        filter.status = status;
      }

      if (typeof search === "string" && search.trim()) {
        filter.name = {
          $regex: escapeRegex(search.trim()),
          $options: "i",
        };
      }

      const result = await menuCollection
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load menu items" });
    }
  },
);

// Admin: Approve or reject menu item
app.patch(
  "/api/admin/menu-items/:id/status",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid pizza ID" });
      }

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({ message: "Invalid status" });
      }

      const result = await menuCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            status,
            updatedAt: new Date(),
          },
        },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json({
        success: true,
        message: `Pizza ${status} successfully`,
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update pizza status" });
    }
  },
);

// Admin: Activate or deactivate pizza
app.patch(
  "/api/admin/menu-items/:id/active",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { isActive } = req.body;

      if (!validObjectId(id) || typeof isActive !== "boolean") {
        return res.status(400).json({ message: "Invalid request" });
      }

      const result = await menuCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            isActive,
            updatedAt: new Date(),
          },
        },
      );

      if (!result.matchedCount) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json({
        success: true,
        message: "Pizza availability updated",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update pizza" });
    }
  },
);

// Admin: Delete menu item
app.delete(
  "/api/admin/menu-items/:id",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!validObjectId(id)) {
        return res.status(400).json({ message: "Invalid pizza ID" });
      }

      const result = await menuCollection.deleteOne({
        _id: new ObjectId(id),
      });

      if (!result.deletedCount) {
        return res.status(404).json({ message: "Pizza not found" });
      }

      res.json({
        success: true,
        message: "Pizza deleted successfully",
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete pizza" });
    }
  },
);

// Admin: View all orders
app.get(
  "/api/admin/orders",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const result = await ordersCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Failed to load orders" });
    }
  },
);

// Admin: View transactions (read only)
app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyRole("admin"),
  async (req, res) => {
    try {
      const result = await transactionsCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      res.json(result);
    } catch (error) {
      res.status(500).json({
        message: "Failed to load transactions",
      });
    }
  },
);

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {
  console.log(`PizzaHub server is running at ${PORT}`);
});
