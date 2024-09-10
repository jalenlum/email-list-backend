/**
 * This code implements a RESTful API using Node.js, Express, and PostgreSQL. 
 * The API provides user authentication with JWT, user registration with email 
 * verification, project management, and the ability to associate and manage emails 
 * with projects. Users can sign up, verify their email, sign in, create and delete 
 * projects, and manage project-related emails. The system also includes secure 
 * password handling with bcrypt, JWT-based authentication, and email sending using 
 * nodemailer.
 * 
 * Key Features:
 * - User registration with email verification
 * - JWT-based user authentication
 * - Project creation and deletion
 * - Email association and management within projects
 * - Secure password storage with bcrypt
 * 
 * Author: Jalen Lum
 * Date: 09/09/2024
 */
const express = require("express");
const { Client } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { v4: uuidv4 } = require("uuid");
const app = express();

dotenv.config();

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

/**
 * Root endpoint to check if the server is running.
 *
 * @return {JSON}   A test message to confirm server status
 */
app.get("/", (req, res) => {
  console.log("test");
  res.json("Bowow");
});

// Database connection
/**
 * Establishes a connection to the PostgreSQL database.
 * 
 * Input: No direct input (uses environment variables for DB credentials).
 * Output: Establishes a persistent connection to the database.
 */
const client = new Client({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

client.connect();

/**
 * Configures nodemailer to send verification emails.
 * 
 * Input: Uses environment variables to set up SMTP server details and authentication.
 * Output: Returns a configured nodemailer transporter for sending emails.
 */
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Sends a verification email to the user after signup.
 *
 * @param {string} userEmail   The email address of the user
 * @param {string} token       The email verification token to include in the email
 * @return {void}              Sends the verification email and logs the result or error
 */
const sendVerificationEmail = (userEmail, token) => {
  const url = `https://email-list-0187bfa72de5.herokuapp.com/verify-email?token=${encodeURIComponent(
    token
  )}`;
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

/**
 * Middleware to authenticate users using JWT tokens.
 *
 * @param {object} req   The HTTP request object
 * @param {object} res   The HTTP response object
 * @param {function} next   The next middleware function to execute if authenticated
 * @return {void}        Proceeds to the next middleware if token is valid, or returns an error status
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

/**
 * Registers a new user and sends a verification email.
 * 
 * @param {object} req   The HTTP request object, containing username, email, and password in the body
 * @param {object} res   The HTTP response object
 * @return {JSON}        A JSON object containing the new user's ID, username, email, and creation date and time
 */
app.post("/users/signup", async (req, res) => {
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

    // Generate UUID for the new user
    const userId = uuidv4();

    // Inserts user into the database
    const insertUserQuery = `
    INSERT INTO users (id, username, email, password_hash, created_at, is_verified, token)
    VALUES ($1, $2, $3, $4, NOW(), FALSE, $5)
    RETURNING id, username, email, created_at
  `;
    const insertUserResult = await client.query(insertUserQuery, [
      userId,
      username,
      email,
      passwordHash,
      token,
    ]);

    // Send verification email
    sendVerificationEmail(email, token);

    const newUser = insertUserResult.rows[0];
    res.status(201).json(newUser);
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Verifies a user's email using a token sent in the verification email.
 * 
 * @param {object} req   The HTTP request object, containing the token in the query
 * @param {object} res   The HTTP response object
 * @return {JSON}        A message indicating whether the email verification was successful
 */
app.get("/verify-email", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: "Invalid token" });
  }

  try {
    const updateQuery =
      "UPDATE users SET is_verified = TRUE WHERE token = $1 RETURNING email";
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

/**
 * Authenticates a user by checking their email/username and password.
 * 
 * @param {object} req   The HTTP request object, containing inputName (email or username) and password in the body
 * @param {object} res   The HTTP response object
 * @return {JSON}        A JWT token if successful, or an error message if authentication fails
 */
app.post("/users/signin", async (req, res) => {
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

    const now = new Date();
    now.setHours(now.getHours() + 1);

    res
      .status(200)
      .json({ token, expires: now.toISOString(), status: "Success" });
  } catch (err) {
    console.error("Error signing in:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Deletes a user along with all their associated projects and project emails.
 * 
 * @param {object} req   The HTTP request object, with the authenticated user attached via JWT
 * @param {object} res   The HTTP response object
 * @return {JSON}        A message indicating successful deletion, or an error message on failure
 */
app.delete("/users/delete", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    await client.query("BEGIN");

    const deleteProjectEmailsQuery = `
      DELETE FROM project_emails
      WHERE project_id IN (
        SELECT id FROM projects WHERE user_id = $1
      )
    `;
    await client.query(deleteProjectEmailsQuery, [userId]);

    const deleteProjectsQuery = "DELETE FROM projects WHERE user_id = $1";
    await client.query(deleteProjectsQuery, [userId]);

    const deleteUserQuery = "DELETE FROM users WHERE id = $1";
    await client.query(deleteUserQuery, [userId]);

    await client.query("COMMIT");

    res.status(200).json({
      message: "User and associated projects and emails deleted successfully",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting user:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Creates a new project for the authenticated user.
 * 
 * @param {object} req   The HTTP request object, with the project_name and description in the body
 * @param {object} res   The HTTP response object
 * @return {JSON}        The newly created project's ID, name, description, and creation date
 */
app.post("/projects/create", authenticateToken, async (req, res) => {
  const { project_name, description } = req.body;
  const userId = req.user.userId; // Extracted from JWT by the middleware

  if (!project_name) {
    return res.status(400).json({ message: "Project name is required" });
  }

  try {
    const insertProjectQuery = `
      INSERT INTO projects (user_id, project_name, description, created_at)
      VALUES ($1, $2, $3, NOW())
      RETURNING id, project_name, description, created_at
    `;
    const insertProjectResult = await client.query(insertProjectQuery, [
      userId,
      project_name,
      description,
    ]);

    const newProject = insertProjectResult.rows[0];
    res.status(201).json(newProject);
  } catch (err) {
    console.error("Error creating project:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Deletes a project and its associated emails.
 * 
 * @param {object} req   The HTTP request object, with project ID in the URL parameters
 * @param {object} res   The HTTP response object
 * @return {JSON}        A success message or an error message if the project is not found
 */
app.delete("/projects/delete/:id", authenticateToken, async (req, res) => {
  const projectId = req.params.id;
  const userId = req.user.userId;

  try {
    await client.query("BEGIN");

    const deleteProjectEmailsQuery =
      "DELETE FROM project_emails WHERE project_id = $1";
    await client.query(deleteProjectEmailsQuery, [projectId]);

    const deleteProjectQuery =
      "DELETE FROM projects WHERE id = $1 AND user_id = $2";
    const deleteProjectResult = await client.query(deleteProjectQuery, [
      projectId,
      userId,
    ]);

    if (deleteProjectResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ message: "Project not found or not owned by the user" });
    }

    await client.query("COMMIT");

    res
      .status(200)
      .json({ message: "Project and associated emails deleted successfully" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting project:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Allows users to add emails to a project.
 * 
 * @param {object} req   The HTTP request object, with project ID in the URL parameters and email in the body
 * @param {object} res   The HTTP response object
 * @return {JSON}        The newly added email for the project
 */
app.post("/send-email/:projectId", async (req, res) => {
  const { projectId } = req.params;
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const checkProjectQuery = "SELECT * FROM projects WHERE id = $1";
    const checkProjectResult = await client.query(checkProjectQuery, [
      projectId,
    ]);

    if (checkProjectResult.rows.length === 0) {
      return res.status(404).json({ message: "Project not found" });
    }

    const checkEmailQuery =
      "SELECT * FROM project_emails WHERE project_id = $1 AND email = $2";
    const checkEmailResult = await client.query(checkEmailQuery, [
      projectId,
      email,
    ]);

    if (checkEmailResult.rows.length > 0) {
      return res
        .status(400)
        .json({ message: "Email already associated with this project" });
    }

    const insertEmailQuery = `
      INSERT INTO project_emails (project_id, email)
      VALUES ($1, $2)
      RETURNING id, project_id, email, added_at
    `;
    const insertEmailResult = await client.query(insertEmailQuery, [
      projectId,
      email,
    ]);

    const newEmail = insertEmailResult.rows[0];
    res.status(201).json(newEmail);
  } catch (err) {
    console.error("Error collecting email:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Retrieves all emails associated with a specific project.
 * 
 * @param {object} req   The HTTP request object, with project ID in the URL parameters
 * @param {object} res   The HTTP response object
 * @return {JSON}        A list of emails associated with the specified project
 */
app.get("/emails/get/:projectId", authenticateToken, async (req, res) => {
  const { projectId } = req.params;
  const userId = req.user.userId;

  try {
    const checkProjectQuery =
      "SELECT * FROM projects WHERE id = $1 AND user_id = $2";
    const checkProjectResult = await client.query(checkProjectQuery, [
      projectId,
      userId,
    ]);

    if (checkProjectResult.rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Project not found or not owned by the user" });
    }

    const getEmailsQuery = "SELECT * FROM project_emails WHERE project_id = $1";
    const getEmailsResult = await client.query(getEmailsQuery, [projectId]);

    res.status(200).json(getEmailsResult.rows);
  } catch (err) {
    console.error("Error retrieving emails:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * Deletes a specific email from a project.
 * 
 * @param {object} req   The HTTP request object, with project ID and email ID in the URL parameters
 * @param {object} res   The HTTP response object
 * @return {JSON}        A success message or an error message if the email is not found
 */
app.delete(
  "/projects/:projectId/emails/delete/:emailId",
  authenticateToken,
  async (req, res) => {
    const { projectId, emailId } = req.params;
    const userId = req.user.userId;

    try {
      const checkProjectQuery =
        "SELECT * FROM projects WHERE id = $1 AND user_id = $2";
      const checkProjectResult = await client.query(checkProjectQuery, [
        projectId,
        userId,
      ]);

      if (checkProjectResult.rows.length === 0) {
        return res
          .status(404)
          .json({ message: "Project not found or not owned by the user" });
      }

      const deleteEmailQuery =
        "DELETE FROM project_emails WHERE id = $1 AND project_id = $2";
      const deleteEmailResult = await client.query(deleteEmailQuery, [
        emailId,
        projectId,
      ]);

      if (deleteEmailResult.rowCount === 0) {
        return res.status(404).json({
          message: "Email not found or not associated with this project",
        });
      }

      res.status(200).json({ message: "Email deleted successfully" });
    } catch (err) {
      console.error("Error deleting email:", err);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);
