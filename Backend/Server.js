const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cookieParser());

const corsOptions = {
  origin: "http://localhost:5173",
  credentials: true,
};
app.use(cors(corsOptions));

const SECRET_KEY = "wesam12341234";
const saltRounds = 10;
let users = [];

app.get("/", (req, res) => {
  res.json(users);
});

app.post("/register", async (req, res) => {
  const { userName, password } = req.body;

  const user = users.find((x) => x.userName === userName);
  if (user) return res.status(400).json({ message: "User already exists" });

  const hashPassword = await bcrypt.hash(password, saltRounds);
  users.push({ userName, password: hashPassword });

  const token = jwt.sign({ userName }, SECRET_KEY, { expiresIn: "1h" });

  res.cookie("authToken", token, { httpOnly: true, secure: false });

  res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { userName, password } = req.body;

  const user = users.find((x) => x.userName === userName);
  if (!user) return res.status(400).json({ message: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Incorrect password" });
  }

  const token = jwt.sign({ userName }, SECRET_KEY, { expiresIn: "1h" });

  res.cookie("authToken", token, {
    httpOnly: true,
    secure: false,
  });

  res.json({ message: "Login successful", token });
});

const authenticateToken = (req, res, next) => {
  const token = req.cookies.authToken; // ✅ إصلاح الخطأ

  if (!token)
    return res
      .status(401)
      .json({ message: "Access Denied. No token provided." });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.user = user;
    next();
  });
};

app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: `Welcome ${req.user.userName}! You have access to protected data.`,
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("authToken");
  res.json({ message: "Logged out successfully" });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
