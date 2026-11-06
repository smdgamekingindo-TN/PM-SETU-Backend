import express, { Router } from "express";
import { requireAuth } from "../../middleware/auth.middleware";
import { requireRoles } from "../../middleware/rbac.middleware";
import { validate } from "../../middleware/validate.middleware";
import { ROLE_CODES } from "../roles/role.constants";
import * as controller from "./integration.controller";
import { integrationIdSchema, integrationListSchema, integrationSourceSchema, integrationIngestSchema, integrationScheduleSchema, integrationEnabledSchema } from "./integration.schema";

const router = Router();
const admin = [ROLE_CODES.SUPER_ADMIN, ROLE_CODES.STATE_PMU_ADMIN];
router.use(requireAuth);
router.get("/", requireRoles(...admin), validate({ query: integrationListSchema }), controller.list);
router.post("/", requireRoles(...admin), validate({ body: integrationSourceSchema }), controller.create);
router.patch("/:id/enabled", requireRoles(...admin), validate({ params: integrationIdSchema, body: integrationEnabledSchema }), controller.enable);
router.patch("/:id/schedule", requireRoles(...admin), validate({ params: integrationIdSchema, body: integrationScheduleSchema }), controller.schedule);
router.post("/:id/ingest", requireRoles(...admin), validate({ params: integrationIdSchema, body: integrationIngestSchema }), controller.ingest);
router.post("/:id/csv", requireRoles(...admin), express.text({ type: ["text/csv", "application/csv"], limit: "1mb" }), validate({ params: integrationIdSchema }), controller.ingestCsv);
router.get("/:id/runs", requireRoles(...admin), validate({ params: integrationIdSchema }), controller.runs);

export const integrationWebhookRouter = Router();
// Webhooks intentionally use HMAC authentication in the controller, not user RBAC.
integrationWebhookRouter.post("/:id", validate({ params: integrationIdSchema }), controller.webhook);
export default router;
