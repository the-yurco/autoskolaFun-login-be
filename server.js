const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();
const MySQLStore = require("express-mysql-session")(session);
const { body, validationResult } = require("express-validator");

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
app.use(
  cors({
    // origin: "https://dev-ucebnicafun.emax-controls.eu",
    origin: "http://localhost:3000",
    credentials: true, // Allow cookies
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
  async (req, res) => {
    // Validation
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

      // Verify password using bcrypt
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Set the session after successful login
      req.session.user = {
        id: user.id,
        name: user.name,
        surname: user.surname,
        role_id: user.role_id,
        city_id: user.city_id,
        age: user.age,
        category: user.category,
      };

      // Respond with the session user data
      res.status(200).json({ user: req.session.user });
    } catch (err) {
      console.error("Error during login:", err);
      res.status(500).json({ message: "Internal server error" });
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

app.post(
  "/forgot-password",
  [
    body("newPassword")
      .isLength({ min: 8 })
      .withMessage("New password must be at least 8 characters long"),
    body("newPasswordConfirmation")
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error("Passwords do not match");
        }
        return true;
      })
      .withMessage("Password confirmation does not match"),
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { newPassword } = req.body;

    if (!req.session.user || !req.session.user.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    const userId = req.session.user.id;

    try {
      // Hash the new password
      const newHashedPassword = await bcrypt.hash(newPassword, 10);

      // Update the password in the database
      const updateQuery = "UPDATE front_users SET password = ? WHERE id = ?";
      await pool.execute(updateQuery, [newHashedPassword, userId]);

      res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      console.error("Error during password change:", err);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
