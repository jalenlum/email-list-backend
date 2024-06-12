const express = require("express");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require("dotenv");
const app = express();

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

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendVerificationEmail = (userEmail, token) => {
  const url = `http://localhost:8080/verify-email?token=${token}`;
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: userEmail,
    subject: "Email Verification",
    text: `Please verify your email by clicking the following link: ${url}`,
    html: `<p>Please verify your email by clicking the following link: <a href="${url}">${url}</a></p>`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return console.log(error);
    }
    console.log("Verification email sent: %s", info.response);
  });
};

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
      return res
        .status(400)
        .json({ message: "This email is already associated with an account" });
    }

    // Checks if username already exists
    const checkUserNameQuery = "SELECT * FROM users WHERE username = $1";
    const checkUserNameResult = await client.query(checkUserNameQuery, [
      username,
    ]);

    if (checkUserNameResult.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "This username is already taken" });
    }

    // Hashes password
    const passwordHash = await bcrypt.hash(password, 13);
    const token = crypto.randomBytes(32).toString("hex");

    // Inserts user into the database
    const insertUserQuery =
      "INSERT INTO users (username, email, password_hash, created_at, is_verified) VALUES ($1, $2, $3, NOW(), FALSE) RETURNING id, username, email, created_at";
    const insertUserResult = await client.query(insertUserQuery, [
      username,
      email,
      passwordHash,
    ]);

    sendVerificationEmail(email, token);

    const newUser = insertUserResult.rows[0];
    res.status(201).json(newUser);
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: "Invalid token" });
  }

  try {
    // Here you would normally verify the token and find the user associated with it
    // For simplicity, let's assume the token is the user's email

    const updateQuery = "UPDATE users SET is_verified = TRUE WHERE email = $1";
    const updateResult = await client.query(updateQuery, [token]);

    if (updateResult.rowCount === 0) {
      return res.status(400).json({ message: "Invalid token" });
    }

    res.status(200).json({ message: "Email verified successfully" });
  } catch (err) {
    console.error("Error during email verification:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/signin", async (req, res) => {
  const { inputName, password } = req.body;

  if (!inputName || !password) {
    return res
      .status(400)
      .json({ message: "Username/email and password are required" });
  }

  try {
    // Checks if the input is username or email format
    let signInQuery;
    if (inputName.includes("@")) {
      signInQuery = "SELECT * FROM users WHERE email = $1";
    } else {
      signInQuery = "SELECT * FROM users WHERE username = $1";
    }

    const signInResult = await client.query(signInQuery, [inputName]);

    if (signInResult.rows.length === 0) {
      return res
        .status(401)
        .json({ message: "Invalid username/email or password" });
    }

    const user = signInResult.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res
        .status(401)
        .json({ message: "Invalid username/email or password" });
    }

    if (!user.is_verified) {
      return res.status(400).json({ message: "Email not verified" });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ token });
  } catch (err) {
    console.error("Error signing in:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/get-users", async (req, res) => {
  try {
    const getUsersQuery = "SELECT * FROM users";
    const getUsersResult = await client.query(getUsersQuery);
    res.status(200).json(getUsersResult.rows);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
