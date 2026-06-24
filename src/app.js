// Essentials
const express = require("express");
require("dotenv").config();
const pool = require("./db");

// Routers
const auth = require("./features/auth/auth.schema");
const authRouter = require("./features/auth/authRouter");
const projectsRouter = require("./features/projects/projectsRouter");

// Libraries
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const cookieParser = require("./middlewares/cookieParser");
const authenticateAccessToken = require("./middlewares/authenticateAccessToken");

const app = express();

// -- Security ----------------------------
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  }),
);

// -- Parsing ------------------------------
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser);

// -- Logging ------------------------------
app.use(morgan("dev"));

// -- Auth ---------------------------------
app.use("/auth", authRouter);
// Putting access token authentication here since below this middleware almost everything require access token to be accessed
app.use(authenticateAccessToken);

// -- Routes -------------------------------
app.get("/protected", (req, res) => {
  res.send("Nuke code: 123123123");
});
// app.get("/app", authenticateAccessToken, (req, res) => {
//   console.log(req.user);
//   res.send(req.user);
// });
app.use("/api", projectsRouter);

// -- 404 ----------------------------------
app.use((req, res) => {
  res.status(404).json({
    error: "not_found",
    message: "Not Found",
  });
});

// -- Error Handler ------------------------
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: "internal_server_error",
    message: "Internal Server Error",
  });
});

module.exports = app;
