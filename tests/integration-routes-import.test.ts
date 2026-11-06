import assert from "node:assert/strict";
import test from "node:test";

test("integration routes load without composing a refined Zod object schema", async () => {
    const routes = await import("../src/modules/integrations/integration.routes");
    assert.ok(routes.default);
});
