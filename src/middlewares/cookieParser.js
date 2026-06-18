const cookieParser = (req, res, next) => {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return next();
  }

  const cookies = cookieHeader.split("; ");
  const parsedCookies = cookies
    .map((cookie) => {
      const parsedCookies = cookie.split("=");
      return { [parsedCookies[0]]: parsedCookies[1] };
    })
    .reduce((acc, item) => {
      return { ...acc, ...item };
    }, {});

  req.cookies = parsedCookies;
  return next();
};

module.exports = cookieParser;
