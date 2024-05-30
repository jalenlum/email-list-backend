const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`Email List Rest API listening on port ${port}`);
});

app.get("/", (req, res) => {
  res.json("Bowow");
});

app.get("/signup", async(req, res) => {
    const query = "SELECT * FROM users WHERE name = ?"
});