const { z } = require("zod");

const registerSchema = z.object({
  name: z
    .string({ message: "Name can't be empty" })
    .min(1, { message: "Name must at least contain 1 character" }),
  email: z.email(),
  password: z
    .string()
    .min(8, { message: "Password must at least contain 8 characters" })
    .regex(/[a-z]/, { message: "Password must at least contain a lowercase" })
    .regex(/[A-Z]/, { message: "Password must at least contain an uppercase" })
    .regex(/[0-9]/, { message: "Password must at least contain a number" })
    .regex(/[^a-zA-Z0-9]/, {
      message:
        "Password must at least contain a special character (!, @, #, etc.)",
    }),
});

const loginSchema = z.object({
  email: z.email(),
  password: z.string({ message: "Password can't be empty" }),
});

module.exports = {
  registerSchema,
  loginSchema,
};
