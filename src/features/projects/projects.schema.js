const { z } = require("zod");

const projectStatus = z.enum(["active", "completed", "archived", "cancelled"], {
  message: "Status must be either active, completed, archived, or cancelled",
});

const addProjectSchema = z.object({
  name: z
    .string({ message: "Name can't be empty" })
    .min(1, { message: "Name must at least contain 1 character" }),
  description: z.string().nullable().optional(),
  due_date: z.string().datetime({ offset: true }).nullable().optional(),
});

const updateProjectSchema = z.object({
  name: z
    .string({ message: "Name can't be empty" })
    .min(1, { message: "Name must at least contain 1 character" }),
  description: z.string().nullable().optional(),
  status: projectStatus,
  due_date: z.string().datetime({ offset: true }).nullable().optional(),
});

module.exports = {
  addProjectSchema,
  updateProjectSchema,
};
