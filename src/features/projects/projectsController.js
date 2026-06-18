const pool = require("../../db");
const { paramsUuidSchema } = require("../../utils/schemas");
const zValidate = require("../../utils/zValidate");
const { addProjectSchema, updateProjectSchema } = require("./projects.schema");

const addProject = async (req, res) => {
  zValidate;
  const validation = zValidate(addProjectSchema, req.body, res);

  if (!validation) return;

  const { name, description, due_date } = validation.data;

  await pool.query(
    `
      INSERT INTO projects (name, description, owner_id, due_date)
      VALUES ($1, $2, $3, $4)
    `,
    [name, description ?? null, req.user.user_id, due_date ?? null],
  );

  res.status(201).json({
    message: "Project created",
  });
};

const updateProject = async (req, res) => {
  const params = zValidate(paramsUuidSchema, req.params, res);
  if (!params) return;

  const validation = zValidate(updateProjectSchema, req.body, res);
  if (!validation) return;

  const { id } = params.data;
  const data = validation.data;

  const result = await pool.query(
    `
    UPDATE projects
    SET 
      name = COALESCE($1, name),
      description = COALESCE($2, description),
      status = COALESCE($3, status),
      due_date = COALESCE($4, due_date),
      updated_at = CURRENT_TIMESTAMP
    WHERE id = $5 AND owner_id = $6
    RETURNING *
    `,
    [
      data.name ?? null,
      data.description ?? null,
      data.status ?? null,
      data.due_date ?? null,
      id,
      req.user.user_id,
    ],
  );

  if (result.rowCount === 0) {
    return res.status(404).json({
      error: "not_found",
      message: "No projects found",
    });
  }

  return res.status(200).json({
    message: "Project updated",
    data: result.rows[0],
  });
};

const deleteProject = async (req, res) => {
  const params = zValidate(paramsUuidSchema, req.params, res);
  if (!params) return;

  const { id } = params.data;

  const result = await pool.query(
    `
      DELETE FROM projects
      WHERE 
        id = $1 
        AND owner_id = $2 
        AND status 
          IN ('archived', 'cancelled')
    `,
    [id, req.user.user_id],
  );

  if (result.rowCount === 0) {
    const check = await pool.query(
      `
        SELECT status
        FROM projects
        WHERE 
          id = $1
          AND owner_id = $2
      `,
      [id, req.user.user_id],
    );

    if (check.rowCount === 0) {
      return res.status(404).json({
        error: "not_found",
        message: "Not found",
      });
    }

    return res.status(400).json({
      error: "bad_input",
      message: "Project must be archived or cancelled before deleting",
    });
  }

  return res.status(204).send();
};

const getAllProjects = async (req, res) => {
  const result = await pool.query(
    `
    SELECT * FROM projects
    WHERE owner_id = $1
    `,
    [req.user.user_id],
  );

  if (result.rowCount === 0) {
    return res.status(404).json({
      error: "not_found",
      message: "No projects found",
    });
  }

  return res.status(200).json({
    data: result.rows,
  });
};

const getProjectById = async (req, res) => {
  const params = paramsUuidSchema.safeParse(req.params);
  if (!params) return;

  const result = await pool.query(
    `
    SELECT * FROM projects
    WHERE
      id = $1
      AND owner_id = $2;
    `,
    [params.id, req.user.user_id],
  );

  if (result.rowCount === 0) {
    return res.status(404).json({
      error: "not_found",
      message: "No projects found",
    });
  }

  return res.status(200).json({
    data: result.rows[0],
  });
};

module.exports = {
  addProject,
  updateProject,
  deleteProject,
  getAllProjects,
  getProjectById,
};
