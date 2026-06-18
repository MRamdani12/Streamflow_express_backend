const express = require("express");
const projectsController = require("./projectsController");
const authenticateAccessToken = require("../../middlewares/authenticateAccessToken");

const router = express.Router();

router.post("/projects", projectsController.addProject);
router.patch("/projects/:id", projectsController.updateProject);
router.delete("/projects/:id", projectsController.deleteProject);
router.get("/projects", projectsController.getAllProjects);
router.get("/projects/:id", projectsController.getProjectById);

module.exports = router;
