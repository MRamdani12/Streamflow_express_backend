const zValidate = (schema, data, res) => {
  const validation = schema.safeParse(data);

  if (!validation.success) {
    res.status(400).json({
      error: "bad_request",
      message: "Input Validation Error",
      validation_errors: validation.error.issues.map((error) => {
        return {
          field: error.path.join("."),
          message: error.message,
        };
      }),
    });

    return null;
  }

  return validation;
};

module.exports = zValidate;
