const express = require("express");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();
const dotenv = require("dotenv");

dotenv.config();

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

app.get("/", (req, res) => {
  res.json("Bowow");
});

const client = new Client({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

client.connect();

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  // Checks to see if all fields are filled out
  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Checks if user email already exists
    const checkUserQuery = "SELECT * FROM users WHERE email = $1";
    const checkUserResult = await client.query(checkUserQuery, [email]);

    if (checkUserResult.rows.length > 0) {
      return res.status(400).json({ message: "This user already exists" });
    }

    // Checks if username already exists
    const checkUserNameQuery = "SELECT * FROM users WHERE username = $1";
    const checkUserNameResult = await client.query(checkUserNameQuery, [
      username,
    ]);

    if (checkUserNameResult.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "This username is already exists" });
    }

    // Hashes password
    const passwordHash = await bcrypt.hash(password, 13);

    // Inserts user into the database
    const insertUserQuery =
      "INSERT INTO users (username, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, username, email, created_at";
    const insertUserResult = await client.query(insertUserQuery, [
      username,
      email,
      passwordHash,
    ]);

    const newUser = insertUserResult.rows[0];
    res.status(201).json(newUser);
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-users", async (req, res) => {
  try {
    const getUsersQuery = "SELECT * FROM users";
    const getUsersResult = await client.query(getUsersQuery);
    res.status(200).json(getUsersResult.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
