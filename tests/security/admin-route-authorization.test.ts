import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface AdminRouterContract {
    path: string;
    routerName: string;
    roleGuard: "router" | "per-route";
}

const adminRouters: AdminRouterContract[] = [
    { path: "src/modules/users/user.routes.ts", routerName: "userRouter", roleGuard: "router" },
    { path: "src/modules/roles/role.routes.ts", routerName: "roleRouter", roleGuard: "router" },
    { path: "src/modules/roles/role.routes.ts", routerName: "permissionRouter", roleGuard: "router" },
    { path: "src/modules/audit/audit.routes.ts", routerName: "auditRouter", roleGuard: "router" },
    { path: "src/modules/documents/document.routes.ts", routerName: "documentAdminRouter", roleGuard: "router" },
    { path: "src/modules/news/news.routes.ts", routerName: "newsAdminRouter", roleGuard: "router" },
    { path: "src/modules/gallery/gallery.routes.ts", routerName: "galleryAdminRouter", roleGuard: "router" },
    { path: "src/modules/banners/banner.routes.ts", routerName: "bannerAdminRouter", roleGuard: "router" },
    { path: "src/modules/contact/contact.routes.ts", routerName: "contactAdminRouter", roleGuard: "per-route" },
];

test("administrative route families authenticate and authorize before validation or upload parsing", () => {
    for (const contract of adminRouters) {
        const source = readFileSync(resolve(process.cwd(), contract.path), "utf8");
        const routerDeclaration = source.indexOf("const " + contract.routerName + " = Router();");

        assert.notEqual(
            routerDeclaration,
            -1,
            contract.path + ": missing " + contract.routerName + " declaration",
        );

        const routePattern = new RegExp(
            "\\b" + contract.routerName + "\\.(?:get|post|patch|put|delete)\\([\\s\\S]*?\\);",
            "g",
        );
        const routeMatches = [...source.matchAll(routePattern)];
        assert.ok(
            routeMatches.length > 0,
            contract.path + ": no routes found for " + contract.routerName,
        );

        const firstRouteIndex = routeMatches[0].index ?? -1;
        const authGuardIndex = source.indexOf(
            contract.routerName + ".use(requireAuth)",
            routerDeclaration,
        );

        assert.notEqual(
            authGuardIndex,
            -1,
            contract.path + ": " + contract.routerName + " is missing requireAuth",
        );
        assert.ok(
            authGuardIndex < firstRouteIndex,
            contract.path + ": " + contract.routerName + " registers a route before requireAuth",
        );

        const routerRoleGuardIndex = source.indexOf(
            contract.routerName + ".use(requireRoles(",
            routerDeclaration,
        );
        if (contract.roleGuard === "router") {
            assert.notEqual(
                routerRoleGuardIndex,
                -1,
                contract.path + ": " + contract.routerName + " is missing router-level requireRoles",
            );
            assert.ok(
                routerRoleGuardIndex < firstRouteIndex,
                contract.path + ": " + contract.routerName + " registers a route before router-level RBAC",
            );
        }

        for (const [index, match] of routeMatches.entries()) {
            const route = match[0];
            const routeStart = match.index ?? -1;
            const routeRoleGuardIndex = route.indexOf("requireRoles(");
            const effectiveRoleGuardIndex = contract.roleGuard === "router"
                ? routerRoleGuardIndex
                : routeRoleGuardIndex === -1 ? -1 : routeStart + routeRoleGuardIndex;

            assert.notEqual(
                effectiveRoleGuardIndex,
                -1,
                contract.path + " route #" + (index + 1) + " is missing an RBAC guard",
            );

            const validationIndex = route.indexOf("validate(");
            if (validationIndex !== -1 && routeRoleGuardIndex !== -1) {
                assert.ok(
                    routeRoleGuardIndex < validationIndex,
                    contract.path + " route #" + (index + 1) + " validates input before route-level RBAC",
                );
            }

            const uploadIndex = route.search(/\.(?:single|array|fields)\(/);
            if (uploadIndex !== -1) {
                assert.ok(
                    effectiveRoleGuardIndex < routeStart + uploadIndex,
                    contract.path + " route #" + (index + 1) + " parses multipart data before RBAC",
                );
            }
        }
    }
});
