/**
 * @file A simple Express.js API for handling email signups.
 * @description This file defines routes for handling email signups and provides basic server configuration.
 * @author Jalen Lum
 * @created 05/28/2024
 */

// Required modules
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
const app = express();

// Middleware
app.use(cors()); // Enables Cross-Origin Resource Sharing (CORS)
app.use(express.json()); // Parses JSON and automatically converts JSON data into a JavaScript Object

// Define the port for the server to listen on
const port = process.env.PORT || 8080;

// Start the server and listen for incoming requests
app.listen(port, () => {
  console.log(`Email List Rest API listening on port ${port}`);
});

app.get("/", (req, res) => {
  res.json("Bowow");
});

/**
 * Route handler for the "/signup" endpoint.
 * @param {import('express').Request} req - The request object.
 * @param {import('express').Response} res - The response object.
 */
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All the fields are required" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 13);


  } catch (error) {
    console.error("Error hashing password:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
