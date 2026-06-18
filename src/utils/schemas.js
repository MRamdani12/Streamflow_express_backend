const { z } = require("zod");

const paramsUuidSchema = z.object({
  id: z
    .string({ message: "ID can't be empty" })
    .uuid({ message: "Invalid UUID" }),
});

module.exports = {
  paramsUuidSchema,
};
