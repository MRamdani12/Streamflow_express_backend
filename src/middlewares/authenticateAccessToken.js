const jwt = require("jsonwebtoken");
require("dotenv").config();

const authenticateAccessToken = (req, res, next) => {
  const accessToken =
    req.cookies?.accessToken ?? req.headers.authorization?.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Unauthorized",
    });
  }

  jwt.verify(accessToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(401).json({
        error: "unauthorized",
        message: "Unauthorized",
      });
    }
    req.user = decoded;
    next();
  });
};

module.exports = authenticateAccessToken;
