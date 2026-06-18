const pool = require("../../db");
const { loginSchema, registerSchema } = require("./auth.schema");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const zValidate = require("../../utils/zValidate");

const FIFTEEN_MINUTES_IN_MILISECONDS = 15 * 60 * 1000;
const SEVEN_DAYS_IN_MILISECONDS = 7 * 24 * 60 * 60 * 1000;
const JWT_EXPIRES_IN = 15 * 60; // 15 minutes
const ACCESS_TOKEN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: false,
  sameSite: "strict",
  maxAge: FIFTEEN_MINUTES_IN_MILISECONDS,
};
const REFRESH_TOKEN_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: false,
  sameSite: "strict",
  maxAge: SEVEN_DAYS_IN_MILISECONDS,
};

const login = async (req, res) => {
  const validation = loginSchema.safeParse(req.body);

  if (!validation.success) {
    return res.status(400).json({
      error: "bad_request",
      message: "Wrong email or password",
    });
  }

  const { email, password } = validation.data;

  try {
    const existingUser = await pool.query(
      `
        SELECT id, name, email, password FROM users WHERE email = $1
      `,
      [email],
    );

    if (existingUser.rowCount === 0) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Wrong email or password",
      });
    }

    const user = existingUser.rows[0];

    const passwordHash = user.password;
    const passwordMatch = await bcrypt.compare(password, passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Wrong email or password",
      });
    }

    const accessToken = jwt.sign(
      {
        user_id: user.id,
        name: user.name,
        email: user.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN },
    );

    const refreshToken = crypto.randomBytes(40).toString("hex");
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await pool.query(
      `
        INSERT INTO refresh_tokens (
          token_hash,
          user_id,
          expires_at
        ) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '7 days')
      `,
      [refreshTokenHash, user.id],
    );

    return res
      .status(200)
      .cookie("accessToken", accessToken, ACCESS_TOKEN_COOKIE_OPTIONS)
      .cookie("refreshToken", refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS)
      .json({
        message: "Login success",
      });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "internal_server_error",
      message: "Internal Server Error",
    });
  }
};

const register = async (req, res) => {
  const validation = zValidate(registerSchema, req.body, res);

  if (!validation) return;

  const newUser = validation.data;

  try {
    const existingUser = await pool.query(
      `
        SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)
      `,
      [newUser.email],
    );

    if (existingUser.rows[0].exists) {
      return res.status(409).json({
        error: "conflict",
        message: "User with that email already exist",
      });
    }

    const passwordHash = await bcrypt.hash(newUser.password, 10);

    const newUserId = await pool.query(
      `
        INSERT INTO users (name, email, password)
        VALUES ($1, $2, $3)
        RETURNING id
      `,
      [newUser.name, newUser.email, passwordHash],
    );

    const accessToken = jwt.sign(
      {
        user_id: newUserId.rows[0].id,
        name: newUser.name,
        email: newUser.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN },
    );

    const refreshToken = crypto.randomBytes(40).toString("hex");
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await pool.query(
      `
        INSERT INTO refresh_tokens (
          token_hash,
          user_id,
          expires_at
        ) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '7 days')
      `,
      [refreshTokenHash, newUserId.rows[0].id],
    );

    return res
      .status(201)
      .cookie("accessToken", accessToken, ACCESS_TOKEN_COOKIE_OPTIONS)
      .cookie("refreshToken", refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS)
      .json({
        message: "User created",
      });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "internal_server_error",
      message: "Internal Server Error",
    });
  }
};

const logout = async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    return res
      .status(200)
      .clearCookie("accessToken", ACCESS_TOKEN_COOKIE_OPTIONS)
      .clearCookie("refreshToken", REFRESH_TOKEN_COOKIE_OPTIONS)
      .json({ message: "Logged out successfuly" });
  }

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const existingRefreshToken = await pool.query(
    `
      UPDATE refresh_tokens
      SET revoked_at = CURRENT_TIMESTAMP
      WHERE token_hash = $1
    `,
    [refreshTokenHash],
  );

  return res
    .status(200)
    .clearCookie("accessToken", ACCESS_TOKEN_COOKIE_OPTIONS)
    .clearCookie("refreshToken", REFRESH_TOKEN_COOKIE_OPTIONS)
    .json({
      message: "Logged out successfuly",
    });
};

const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Unauthorized",
    });
  }

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  try {
    // Selecting the needed data from the DB by joining both the users and refresh_tokens table;
    const existingRefreshToken = await pool.query(
      `
      SELECT u.id AS user_id, u.name AS user_name, u.email AS user_email, rt.revoked_at
      FROM refresh_tokens rt
      JOIN users u
        ON rt.user_id = u.id
      WHERE rt.token_hash = $1
      AND rt.expires_at > CURRENT_TIMESTAMP
      `,
      [refreshTokenHash],
    );

    // Checking if refresh token exist
    if (existingRefreshToken.rowCount === 0) {
      return res.status(401).json({
        error: "invalid_token",
        message: "Unauthorized",
      });
    }

    const { user_id, user_name, user_email, revoked_at } =
      existingRefreshToken.rows[0];

    // If token is revoked already, nuke the refresh tokens for that user since it's been compromised.
    if (!!revoked_at) {
      console.log(
        `Token compromised, revoking every tokens for user: ${user_id}-${user_name}-${user_email}`,
      );
      await pool.query(
        `
        UPDATE refresh_tokens
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE user_id = $1
        AND revoked_at IS NULL
        `,
        [user_id],
      );

      return res.status(401).json({
        error: "invalid_token",
        message: "Unauthorized",
      });
    }
    const newAccessToken = jwt.sign(
      {
        user_id,
        name: user_name,
        email: user_email,
      },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN },
    );
    const newRefreshToken = crypto.randomBytes(40).toString("hex");
    const newRefreshTokenHash = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    // Using CTE(Common Table Expression)
    // Work like this
    // make a temporary table called revoked_token which the value came from RETURNING after UPDATE (user_id and id in this case)
    // and then inserting it into the database by using SELECT.
    await pool.query(
      `
        WITH revoked_token AS (
          UPDATE refresh_tokens
          SET revoked_at = CURRENT_TIMESTAMP
          WHERE token_hash = $1
          AND revoked_at IS NULL
          RETURNING user_id, id AS parent_id
        )
        INSERT INTO refresh_tokens (user_id, token_hash, parent_id, expires_at)
        SELECT user_id, $2, parent_id, CURRENT_TIMESTAMP + INTERVAL '7 days'
        FROM revoked_token
      `,
      [refreshTokenHash, newRefreshTokenHash],
    );

    return res
      .status(201)
      .cookie("accessToken", newAccessToken, ACCESS_TOKEN_COOKIE_OPTIONS)
      .cookie("refreshToken", newRefreshToken, REFRESH_TOKEN_COOKIE_OPTIONS)
      .json({
        message: "Access token refreshed",
      });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "internal_server_error",
      message: "Internal Server Error",
    });
  }
};

const me = async (req, res) => {
  res.status(200).json({
    user_id: req.user.user_id,
    name: req.user.name,
    email: req.user.email,
  });
};

module.exports = {
  login,
  register,
  logout,
  refreshToken,
  me,
};
