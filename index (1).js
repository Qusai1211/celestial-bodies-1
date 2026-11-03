import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import * as db from "./utils/db.js";
import watchlistRouter from "./routes/watchlist.js";

const app = express();

app.use(express.json());

const SECRET = process.env.JWT_SECRET || "secret";

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required"
    });
  }

  const user = db.findByUsername(username);

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials"
    });
  }

  try {
    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        role: user.role
      },
      SECRET,
      { expiresIn: "1h" }
    );

    return res.status(200).json({ token });
  } catch (error) {
    return res.status(500).json({
      error: error.message
    });
  }
});

app.use("/api/watchlist", watchlistRouter);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});