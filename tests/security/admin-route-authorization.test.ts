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

function getRouteRegistrations(source: string, routerName: string): string[] {
    const escapedName = routerName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(
        `\\b${escapedName}\\.(?:get|post|patch|put|delete)\\([\\s\\S]*?\\);`,
        "g",
    );
    return [...source.matchAll(pattern)].map((match) => match[0]);
}

test("administrative route families authenticate and authorize before validation or upload parsing", () => {
    for (const contract of adminRouters) {
        const source = readFileSync(resolve(process.cwd(), contract.path), "utf8");
        const routerDeclaration = source.indexOf(`const ${contract.routerName} = Router();`);

        assert.notEqual(
            routerDeclaration,
            -1,
            `${contract.path}: missing ${contract.routerName} declaration`,
        );

        const routeCalls = getRouteRegistrations(source, contract.routerName);
        assert.ok(routeCalls.length > 0, `${contract.path}: no routes found for ${contract.routerName}`);

        const firstRouteIndex = source.indexOf(`${contract.routerName}.${routeCalls[0].match(/\.(get|post|patch|put|delete)\(/)?.[1]}(`);
        const authGuardIndex = source.indexOf(`${contract.routerName}.use(requireAuth)`, routerDeclaration);

        assert.notEqual(authGuardIndex, -1, `${contract.path}: ${contract.routerName} is missing requireAuth`);
        assert.ok(
            authGuardIndex < firstRouteIndex,
            `${contract.path}: ${contract.routerName} registers a route before requireAuth`,
        );

        const routerRoleGuardIndex = source.indexOf(`${contract.routerName}.use(requireRoles(`, routerDeclaration);
        if (contract.roleGuard === "router") {
            assert.notEqual(
                routerRoleGuardIndex,
                -1,
                `${contract.path}: ${contract.routerName} is missing router-level requireRoles`,
            );
            assert.ok(
                routerRoleGuardIndex < firstRouteIndex,
                `${contract.path}: ${contract.routerName} registers a route before router-level RBAC`,
            );
        }

        for (const [index, route] of routeCalls.entries()) {
            const routeRoleGuardIndex = route.indexOf("requireRoles(");
            const effectiveRoleGuardIndex = contract.roleGuard === "router"
                ? routerRoleGuardIndex
                : routeRoleGuardIndex;

            assert.notEqual(
                effectiveRoleGuardIndex,
                -1,
                `${contract.path} route #${index + 1} is missing an RBAC guard`,
            );

            const validationIndex = route.indexOf("validate(");
            if (validationIndex !== -1 && routeRoleGuardIndex !== -1) {
                assert.ok(
                    routeRoleGuardIndex < validationIndex,
                    `${contract.path} route #${index + 1} validates input before route-level RBAC`,
                );
            }

            const uploadIndex = route.search(/\\.(?:single|array|fields)\\(/);
            if (uploadIndex !== -1 && routeRoleGuardIndex !== -1) {
                assert.ok(
                    routeRoleGuardIndex < uploadIndex,
                    `${contract.path} route #${index + 1} parses multipart data before route-level RBAC`,
                );
            }
        }
    }
});
