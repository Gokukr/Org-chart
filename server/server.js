const express = require("express");
const env = require("dotenv").config();
const app = express();
app.use(express.json());
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
app.use(cors());
app.get("/users", async (req, res) => {
  try {
    const employees = await prisma.employees.findMany();
    console.log(employees);
    res.json(employees);
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: error });
  }
});
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const userExists = await prisma.users.findUnique({ where: { username } });
  if (userExists) {
    return res.status(400).send("User already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.users.create({
    data: {
      username,
      password: hashedPassword,
    },
  });
  console.log("created user", user);

  res.status(201).send("User registered successfully");
});

app.post("/", async (req, res) => {
  const { username, password } = req.body;

  const user = await prisma.users.findUnique({ where: { username } });
  if (!user) {
    return res.status(400).send("Invalid username or password");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send("Invalid username or password");
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
  res.json({ token });
});

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  // console.log("Authorization Header:", authHeader); // Add this line to log the authorization header

  const token = authHeader && authHeader.split(" ")[1];
  // console.log("Token:", token); // Add this line to log the token

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verification Error:", err); // Add this line to log the error
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

module.exports = authenticateJWT;

app.get("/protected", authenticateJWT, (req, res) => {
  res.json({ message: "You are authorized", user: req.user });
});
app.listen(4000, () => {
  console.log("Server is running on port 4000");
});
