const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();
const MySQLStore = require("express-mysql-session")(session);
const { body, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");

const app = express();
// const cors = require("cors");

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Session store configuration
const sessionStore = new MySQLStore({}, pool);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
const allowedOrigins = [
  // "http://localhost:3000",
  "https://dev-ucebnicafun.emax-controls.eu",
  // "https://ucebnicafun.emax-controls.eu",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(
  session({
    key: "session_cookie_name",
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: false, //localhost false
      httpOnly: false, //localhost false
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.get("/", (req, res) => {
  res.send("Backend server is running");
});

app.post(
  "/login",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("surname").notEmpty().withMessage("Surname is required"),
    body("password").notEmpty().withMessage("Password is required"),
    body("role_id").isInt().withMessage("Role ID must be an integer"),
    body("city_id").isInt().withMessage("City ID must be an integer"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, surname, password, role_id, city_id } = req.body;

    try {
      const query = `
        SELECT id, name, surname, password, role_id, city_id, age, category
        FROM front_users
        WHERE name = ? AND surname = ? AND role_id = ? AND city_id = ?`;
      const [results] = await pool.execute(query, [
        name,
        surname,
        role_id,
        city_id,
      ]);

      if (results.length === 0) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Generate JWT
      const token = jwt.sign(
        {
          id: user.id,
          name: user.name,
          surname: user.surname,
          role_id: user.role_id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      res.status(200).json({
        message: "Login successful",
        token, // Send token to the client
      });
    } catch (err) {
      next(err); // Pass error to error-handling middleware
    }
  }
);

// Check authentication status
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.status(200).json(req.session.user);
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
});
// Logout route
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Failed to log out" });
    }
    res.clearCookie("session_cookie_name");
    res.status(200).json({ message: "Logged out successfully" });
  });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token missing" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user; // Attach user to request object
    next();
  });
};

app.get("/protected", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Welcome to the protected route!" });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

app.post(
  "/forgot-password",
  [
    // Validate inputs
    body("email").isEmail().withMessage("A valid email is required"),
    body("name").notEmpty().withMessage("Name is required"),
    body("surname").notEmpty().withMessage("Surname is required"),
    body("newPassword")
      .isLength({ min: 8 })
      .withMessage("New password must be at least 8 characters long"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, name, surname, newPassword } = req.body;

    try {
      // Check if the user with the given email exists
      const userQuery = `
        SELECT id, name, surname
        FROM front_users
        WHERE email = ?
      `;
      const [users] = await pool.execute(userQuery, [email]);

      if (users.length === 0) {
        return res
          .status(404)
          .json({ message: "No user found with the provided email address" });
      }

      const user = users[0];

      // Verify name and surname
      if (user.name !== name || user.surname !== surname) {
        return res.status(400).json({
          message: "The provided name and surname do not match our records.",
        });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update the password in the database
      const updateQuery = `
        UPDATE front_users
        SET password = ?
        WHERE id = ?
      `;
      await pool.execute(updateQuery, [hashedPassword, user.id]);

      res
        .status(200)
        .json({ message: "Password reset successfully. You can now log in." });
    } catch (err) {
      console.error("Error during password reset:", err);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
