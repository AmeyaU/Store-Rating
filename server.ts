/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import { UserRole } from "./src/types";

const app = express();
const PORT = 3000;
const DB_FILE = path.join(process.cwd(), "db.json");

app.use(express.json());

// --- Database Logic ---
interface DBStructure {
  users: any[];
  stores: any[];
  ratings: any[];
}

function getInitialData(): DBStructure {
  return {
    users: [
      {
        id: "usr_admin",
        name: "System Administrator Office", // 28 chars
        email: "admin@storerating.com",
        password: "AdminPass@123", // 13 chars, meets requirements
        address: "Central Secretariat, 100 System Admin Avenue, California 94016",
        role: UserRole.Admin,
      },
      {
        id: "usr_nolan",
        name: "Christopher Nolan Store Owner Account", // 37 chars
        email: "nolan.owner@gmail.com",
        password: "NolanOwner@123", // 14 chars
        address: "Warner Bros Estates, Hollywood Hills, Los Angeles, CA 90028",
        role: UserRole.StoreOwner,
      },
      {
        id: "usr_ramsay",
        name: "Gordon Ramsay Gourmet Store Owner", // 33 chars
        email: "gordon.owner@gmail.com",
        password: "GordonOwner@123", // 15 chars
        address: "Ramsay Gastronomy HQ, High Street, Chelsea, London SW3 4UT",
        role: UserRole.StoreOwner,
      },
      {
        id: "usr_user1",
        name: "Regular Shopper First Customer", // 30 chars
        email: "shopper.one@gmail.com",
        password: "ShopperOne@123", // 14 chars
        address: "Oakwood Residential Complex, Block C, Apt 314, San Francisco CA",
        role: UserRole.Normal,
      },
      {
        id: "usr_user2",
        name: "Sarah Connor Terminator Avenger", // 31 chars
        email: "sarah.connor@sky.net",
        password: "SarahConnor@123", // 15 chars
        address: "Abandoned Desert Outpost Underground Bunker, Mojave, NV 89012",
        role: UserRole.Normal,
      }
    ],
    stores: [
      {
        id: "str_nolan",
        name: "Nolan Cinematic Merchandise Store", // 33 chars
        email: "nolan.store@gmail.com",
        address: "Universal Studios Parkway, Building A-12, Hollywood, CA 91608",
        ownerId: "usr_nolan",
      },
      {
        id: "str_ramsay",
        name: "Ramsay Gourmet Culinary Store", // 29 chars
        email: "ramsay.store@gmail.com",
        address: "The Savoy Culinary Court, Strand, London WC2R 0EZ, UK",
        ownerId: "usr_ramsay",
      }
    ],
    ratings: [
      {
        id: "rat_1",
        userId: "usr_user1",
        storeId: "str_nolan",
        rating: 5,
        createdAt: new Date("2026-06-12T10:30:00Z").toISOString(),
      },
      {
        id: "rat_2",
        userId: "usr_user2",
        storeId: "str_nolan",
        rating: 4,
        createdAt: new Date("2026-06-13T14:45:00Z").toISOString(),
      },
      {
        id: "rat_3",
        userId: "usr_user1",
        storeId: "str_ramsay",
        rating: 4,
        createdAt: new Date("2026-06-14T09:15:00Z").toISOString(),
      },
      {
        id: "rat_4",
        userId: "usr_user2",
        storeId: "str_ramsay",
        rating: 5,
        createdAt: new Date("2026-06-15T18:20:00Z").toISOString(),
      }
    ],
  };
}

function readDB(): DBStructure {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const initData = getInitialData();
      fs.writeFileSync(DB_FILE, JSON.stringify(initData, null, 2), "utf-8");
      return initData;
    }
    const raw = fs.readFileSync(DB_FILE, "utf-8");
    return JSON.parse(raw);
  } catch (err) {
    console.error("Error reading database file, resetting to base", err);
    return getInitialData();
  }
}

function writeDB(data: DBStructure) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf-8");
  } catch (err) {
    console.error("Error writing database file", err);
  }
}

// Ensure database file initializes
readDB();

// --- Validation Helpers ---
function validateName(name: string): string | null {
  if (!name) return "Name is required.";
  if (name.length < 20 || name.length > 60) {
    return "Name must be between 20 and 60 characters long.";
  }
  return null;
}

function validateAddress(address: string): string | null {
  if (!address) return "Address is required.";
  if (address.length > 400) {
    return "Address must be at most 400 characters.";
  }
  return null;
}

function validateEmail(email: string): string | null {
  if (!email) return "Email is required.";
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return "Invalid email format.";
  }
  return null;
}

function validatePassword(password: string): string | null {
  if (!password) return "Password is required.";
  if (password.length < 8 || password.length > 16) {
    return "Password must be between 8 and 16 characters long.";
  }
  const hasUpperCase = /[A-Z]/.test(password);
  const hasSpecialChar = /[^A-Za-z0-9]/.test(password);
  if (!hasUpperCase) {
    return "Password must contain at least one uppercase letter.";
  }
  if (!hasSpecialChar) {
    return "Password must contain at least one special character.";
  }
  return null;
}

// --- Auth Middleware ---
function authenticateUser(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized access: Bearer token is missing." });
    return;
  }
  const userId = authHeader.split(" ")[1];
  const db = readDB();
  const user = db.users.find((u) => u.id === userId);
  if (!user) {
    res.status(401).json({ error: "Unauthorized access: User not found." });
    return;
  }
  (req as any).user = user;
  next();
}

// --- API Endpoints ---

// User details helper excluding password
const cleanUser = (u: any) => {
  const { password, ...rest } = u;
  return rest;
};

// 1. Auth Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: "Email and password are required." });
    return;
  }

  const db = readDB();
  const user = db.users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase() && u.password === password
  );

  if (!user) {
    res.status(401).json({ error: "Invalid email or password." });
    return;
  }

  res.json({
    token: user.id,
    user: cleanUser(user),
  });
});

// 2. Auth Signup (Normal User only)
app.post("/api/auth/signup", (req, res) => {
  const { name, email, address, password } = req.body;

  // Run rigorous validations
  const nameErr = validateName(name);
  if (nameErr) { res.status(400).json({ error: nameErr }); return; }

  const emailErr = validateEmail(email);
  if (emailErr) { res.status(400).json({ error: emailErr }); return; }

  const addressErr = validateAddress(address);
  if (addressErr) { res.status(400).json({ error: addressErr }); return; }

  const passErr = validatePassword(password);
  if (passErr) { res.status(400).json({ error: passErr }); return; }

  const db = readDB();
  if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    res.status(400).json({ error: "Email already registered on this platform." });
    return;
  }

  const newUser = {
    id: "usr_" + Math.random().toString(36).substring(2, 11),
    name,
    email: email.toLowerCase(),
    password,
    address,
    role: UserRole.Normal,
  };

  db.users.push(newUser);
  writeDB(db);

  res.status(201).json({
    token: newUser.id,
    user: cleanUser(newUser),
  });
});

// 3. Update Password
app.post("/api/auth/update-password", authenticateUser, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = (req as any).user;

  if (!currentPassword || !newPassword) {
    res.status(400).json({ error: "Current password and new password are required." });
    return;
  }

  const db = readDB();
  const dbUserIndex = db.users.findIndex((u) => u.id === user.id);
  if (dbUserIndex === -1) {
    res.status(404).json({ error: "User not found." });
    return;
  }

  const dbUser = db.users[dbUserIndex];
  if (dbUser.password !== currentPassword) {
    res.status(400).json({ error: "Incorrect current password." });
    return;
  }

  const passErr = validatePassword(newPassword);
  if (passErr) {
    res.status(400).json({ error: passErr });
    return;
  }

  dbUser.password = newPassword;
  db.users[dbUserIndex] = dbUser;
  writeDB(db);

  res.json({ message: "Password updated successfully." });
});

// 4. View Stores (Normal and Admin and Owners)
app.get("/api/stores", authenticateUser, (req, res) => {
  const user = (req as any).user;
  const db = readDB();

  // Compute stats for stores
  const storeListings = db.stores.map((store) => {
    const storeRatings = db.ratings.filter((r) => r.storeId === store.id);
    const totalRatings = storeRatings.length;
    const overallRating =
      totalRatings > 0
        ? parseFloat((storeRatings.reduce((sum, r) => sum + r.rating, 0) / totalRatings).toFixed(1))
        : 0;

    let userRating: number | undefined;
    if (user.role === UserRole.Normal) {
      const myRating = storeRatings.find((r) => r.userId === user.id);
      userRating = myRating ? myRating.rating : undefined;
    }

    return {
      ...store,
      overallRating,
      totalRatings,
      userRating,
    };
  });

  res.json(storeListings);
});

// 5. Submit or edit a store rating (Normal User only)
app.post("/api/ratings", authenticateUser, (req, res) => {
  const user = (req as any).user;
  if (user.role !== UserRole.Normal) {
    res.status(403).json({ error: "Forbidden: Only normal users can rate stores." });
    return;
  }

  const { storeId, rating } = req.body;
  const ratingNum = Number(rating);

  if (!storeId || isNaN(ratingNum) || ratingNum < 1 || ratingNum > 5) {
    res.status(400).json({ error: "Rating must be an integer between 1 and 5." });
    return;
  }

  const db = readDB();
  const store = db.stores.find((s) => s.id === storeId);
  if (!store) {
    res.status(404).json({ error: "Store not found." });
    return;
  }

  const existingIndex = db.ratings.findIndex((r) => r.storeId === storeId && r.userId === user.id);

  if (existingIndex !== -1) {
    // Update existing
    db.ratings[existingIndex].rating = ratingNum;
    db.ratings[existingIndex].createdAt = new Date().toISOString();
  } else {
    // Insert new
    db.ratings.push({
      id: "rat_" + Math.random().toString(36).substring(2, 11),
      userId: user.id,
      storeId,
      rating: ratingNum,
      createdAt: new Date().toISOString(),
    });
  }

  writeDB(db);
  res.json({ message: "Store rated successfully." });
});

// 6. Admin Stats
app.get("/api/admin/stats", authenticateUser, (req, res) => {
  const user = (req as any).user;
  if (user.role !== UserRole.Admin) {
    res.status(403).json({ error: "Forbidden: Admin access only." });
    return;
  }

  const db = readDB();
  res.json({
    totalUsers: db.users.length,
    totalStores: db.stores.length,
    totalRatings: db.ratings.length,
  });
});

// 7. Admin View All Users
app.get("/api/admin/users", authenticateUser, (req, res) => {
  const user = (req as any).user;
  if (user.role !== UserRole.Admin) {
    res.status(403).json({ error: "Forbidden: Admin access only." });
    return;
  }

  const db = readDB();
  const enhancedUsers = db.users.map((u) => {
    const cleanU = cleanUser(u);
    if (u.role === UserRole.StoreOwner) {
      const storeObj = db.stores.find((s) => s.ownerId === u.id);
      if (storeObj) {
        cleanU.storeName = storeObj.name;
        const storeRatings = db.ratings.filter((r) => r.storeId === storeObj.id);
        const ratingCount = storeRatings.length;
        cleanU.storeRating =
          ratingCount > 0
            ? parseFloat((storeRatings.reduce((sum, r) => sum + r.rating, 0) / ratingCount).toFixed(1))
            : 0;
      } else {
        cleanU.storeName = "No store assigned";
        cleanU.storeRating = 0;
      }
    }
    return cleanU;
  });

  res.json(enhancedUsers);
});

// 8. Admin Add User (Admin, Normal User, or Store Owner)
app.post("/api/admin/users", authenticateUser, (req, res) => {
  const adminUser = (req as any).user;
  if (adminUser.role !== UserRole.Admin) {
    res.status(403).json({ error: "Forbidden: Admin access only." });
    return;
  }

  const { name, email, password, address, role } = req.body;
  const roleNum = Number(role);

  // Run rigorous validations
  const nameErr = validateName(name);
  if (nameErr) { res.status(400).json({ error: nameErr }); return; }

  const emailErr = validateEmail(email);
  if (emailErr) { res.status(400).json({ error: emailErr }); return; }

  const addressErr = validateAddress(address);
  if (addressErr) { res.status(400).json({ error: addressErr }); return; }

  const passErr = validatePassword(password);
  if (passErr) { res.status(400).json({ error: passErr }); return; }

  if (![UserRole.Admin, UserRole.Normal, UserRole.StoreOwner].includes(roleNum)) {
    res.status(400).json({ error: "Invalid role specified." });
    return;
  }

  const db = readDB();
  if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    res.status(400).json({ error: "A user with this email already exists." });
    return;
  }

  const newUser = {
    id: "usr_" + Math.random().toString(36).substring(2, 11),
    name,
    email: email.toLowerCase(),
    password,
    address,
    role: roleNum,
  };

  db.users.push(newUser);
  writeDB(db);

  res.status(201).json({
    message: "User registered successfully.",
    user: cleanUser(newUser),
  });
});

// 9. Admin Add Store
app.post("/api/admin/stores", authenticateUser, (req, res) => {
  const adminUser = (req as any).user;
  if (adminUser.role !== UserRole.Admin) {
    res.status(403).json({ error: "Forbidden: Admin access only." });
    return;
  }

  const { name, email, address, ownerId } = req.body;

  // Run validations
  const nameErr = validateName(name);
  if (nameErr) { res.status(400).json({ error: nameErr }); return; }

  const emailErr = validateEmail(email);
  if (emailErr) { res.status(400).json({ error: emailErr }); return; }

  const addressErr = validateAddress(address);
  if (addressErr) { res.status(400).json({ error: addressErr }); return; }

  if (!ownerId) {
    res.status(400).json({ error: "An owner account is required for the store." });
    return;
  }

  const db = readDB();

  // Verify specified owner exists and is role 3
  const owner = db.users.find((u) => u.id === ownerId);
  if (!owner) {
    res.status(404).json({ error: "Specified owner account does not exist." });
    return;
  }
  if (owner.role !== UserRole.StoreOwner) {
    res.status(400).json({ error: "Specified owner must have the 'Store Owner' role." });
    return;
  }

  // Ensure owner doesn't already own a store (1 owner to 1 store relationship)
  if (db.stores.some((s) => s.ownerId === ownerId)) {
    res.status(400).json({ error: "Selected user already owns another store." });
    return;
  }

  const newStore = {
    id: "str_" + Math.random().toString(36).substring(2, 11),
    name,
    email: email.toLowerCase(),
    address,
    ownerId,
  };

  db.stores.push(newStore);
  writeDB(db);

  res.status(201).json({
    message: "Store created successfully.",
    store: newStore,
  });
});

// 9b. Admin Delete Store
app.delete("/api/admin/stores/:id", authenticateUser, (req, res) => {
  const adminUser = (req as any).user;
  if (adminUser.role !== UserRole.Admin) {
    res.status(403).json({ error: "Forbidden: Admin access only." });
    return;
  }

  const { id } = req.params;
  const db = readDB();

  const storeExists = db.stores.some((s) => s.id === id);
  if (!storeExists) {
    res.status(404).json({ error: "Store not found." });
    return;
  }

  db.stores = db.stores.filter((s) => s.id !== id);
  db.ratings = db.ratings.filter((r) => r.storeId !== id);
  writeDB(db);

  res.json({ message: "Store deleted successfully." });
});

// 10. Store Owner Dashboard Details
app.get("/api/owner/dashboard", authenticateUser, (req, res) => {
  const user = (req as any).user;
  if (user.role !== UserRole.StoreOwner) {
    res.status(403).json({ error: "Forbidden: Store Owner access only." });
    return;
  }

  const db = readDB();
  const store = db.stores.find((s) => s.ownerId === user.id);
  if (!store) {
    res.json({
      hasStore: false,
      message: "You do not currently have a store assigned by the administrator.",
      averageRating: 0,
      ratings: [],
    });
    return;
  }

  const storeRatings = db.ratings
    .filter((r) => r.storeId === store.id)
    .map((r) => {
      const ratedByUser = db.users.find((u) => u.id === r.userId);
      return {
        id: r.id,
        rating: r.rating,
        createdAt: r.createdAt,
        userName: ratedByUser ? ratedByUser.name : "Anonymous User",
        userEmail: ratedByUser ? ratedByUser.email : "N/A",
        userAddress: ratedByUser ? ratedByUser.address : "N/A",
      };
    });

  const ratingCount = storeRatings.length;
  const averageRating =
    ratingCount > 0
      ? parseFloat((storeRatings.reduce((sum, r) => sum + r.rating, 0) / ratingCount).toFixed(1))
      : 0;

  res.json({
    hasStore: true,
    store,
    averageRating,
    totalRatings: ratingCount,
    ratings: storeRatings,
  });
});

// --- Server-Side Setup for Vite Single Entry File Serving ---

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
