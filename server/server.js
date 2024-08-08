const express = require("express");
const env = require("dotenv").config();
const app = express();
app.use(express.json());
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const cors = require("cors");
const pg = require("pg");
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
app.get("/get-employee-data", async (req, res) => {
  try {
    const result = await prisma.$queryRaw`
      SELECT
          e.employee_id,
          e.name AS employee_name,
          r.role_name AS employee_role,
          STRING_AGG(DISTINCT s.name, ', ') AS supervisor_names,
          STRING_AGG(DISTINCT sub.name, ', ') AS subordinate_names
      FROM
          employees e
      LEFT JOIN
          roles r ON e.role_id = r.role_id
      LEFT JOIN
          organization o_supervisor ON e.employee_id = o_supervisor.subordinate_id
      LEFT JOIN
          employees s ON o_supervisor.supervisor_id = s.employee_id
      LEFT JOIN
          organization o_subordinate ON e.employee_id = o_subordinate.supervisor_id
      LEFT JOIN
          employees sub ON o_subordinate.subordinate_id = sub.employee_id
      GROUP BY
          e.employee_id, e.name, r.role_name
      ORDER BY
          e.employee_id;
    `;
    res.json(result);
  } catch (error) {
    console.error("Error executing query:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/details", async (req, res) => {
  try {
    const result = await prisma.$queryRaw`
      SELECT
          e.name AS employee_name,
          r.role_name AS employee_role,
          s.name AS supervisor_name
      FROM
          employees e
      LEFT JOIN
          roles r ON e.role_id = r.role_id
      INNER JOIN
          organization o ON e.employee_id = o.subordinate_id
      INNER JOIN
          employees s ON o.supervisor_id = s.employee_id
      ORDER BY
          e.name;
    `;
    res.json(result);
  } catch (error) {
    console.error("Error executing query:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/", async (req, res) => {
  const { username, password } = req.body;

  // Fetch the user from the database
  const user = await prisma.users.findUnique({ where: { username } });
  if (!user) {
    return res.status(400).send("Invalid username or password");
  }

  // Check if the password is correct
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send("Invalid username or password");
  }

  // Create the JWT token including the role
  const token = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  // Send the token in the response
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
app.put("/update-role/:employeeId", authenticateJWT, async (req, res) => {
  const { employeeId } = req.params;
  const { newRoleId } = req.body;

  try {
    const updatedEmployee = await prisma.employees.update({
      where: { employee_id: employeeId },
      data: { role_id: newRoleId },
    });

    res.json(updatedEmployee);
  } catch (error) {
    console.error("Error updating role:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/protected", authenticateJWT, (req, res) => {
  res.json({ message: "You are authorized", user: req.user });
});
app.listen(4000, () => {
  console.log("Server is running on port 4000");
});
