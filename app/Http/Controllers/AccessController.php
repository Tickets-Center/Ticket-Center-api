<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

/**
 * Spatie-backed role and permission management for the admin UI.
 *
 * The controller deliberately keeps all writes on Spatie's own models and
 * relationships (syncPermissions, roles(), users()) so the package's guards,
 * pivots and cache invalidation stay authoritative.
 */
class AccessController extends Controller
{
    private const GUARD = 'web';

    private const PROTECTED_ROLE = 'admin';

    /*
    |--------------------------------------------------------------------------
    | GET /api/admin/roles/manage — roles with permissions + user counts
    |--------------------------------------------------------------------------
    */
    public function roleIndex()
    {
        $userCounts = $this->roleUserCounts();

        $roles = Role::query()
            ->with(['permissions:id,name'])
            ->orderBy('name')
            ->get()
            ->map(fn (Role $role) => $this->formatRole(
                $role,
                (int) ($userCounts[$role->id] ?? 0)
            ));

        return response()->json($roles);
    }

    /*
    |--------------------------------------------------------------------------
    | POST /api/admin/roles — create a role and optionally assign permissions
    |--------------------------------------------------------------------------
    */
    public function roleStore(Request $request)
    {
        $data = $request->validate([
            'name'        => [
                'required',
                'string',
                'max:50',
                'regex:/^[A-Za-z0-9][A-Za-z0-9 _-]*$/',
                Rule::unique('roles', 'name')->where(
                    fn ($query) => $query->where('guard_name', self::GUARD)
                ),
            ],
            'permissions'   => ['sometimes', 'array'],
            'permissions.*' => ['integer', 'exists:permissions,id'],
        ]);

        $role = Role::create([
            'name'       => trim($data['name']),
            'guard_name' => self::GUARD,
        ]);

        if ($request->has('permissions')) {
            $role->syncPermissions($this->permissionModels($data['permissions'] ?? []));
        }

        $role->load('permissions');

        return response()->json([
            'message' => 'Role created successfully.',
            'role'    => $this->formatRole($role, 0),
        ], 201);
    }

    /*
    |--------------------------------------------------------------------------
    | PATCH /api/admin/roles/{role} — rename and/or sync permissions
    |--------------------------------------------------------------------------
    */
    public function roleUpdate(Request $request, Role $role)
    {
        $data = $request->validate([
            'name'          => [
                'sometimes',
                'required',
                'string',
                'max:50',
                'regex:/^[A-Za-z0-9][A-Za-z0-9 _-]*$/',
                Rule::unique('roles', 'name')
                    ->ignore($role->id)
                    ->where(fn ($query) => $query->where('guard_name', self::GUARD)),
            ],
            'permissions'   => ['sometimes', 'array'],
            'permissions.*' => ['integer', 'exists:permissions,id'],
        ]);

        if (
            $role->name === self::PROTECTED_ROLE
            && isset($data['name'])
            && trim($data['name']) !== $role->name
        ) {
            return response()->json([
                'message' => 'The system admin role cannot be renamed.',
            ], 422);
        }

        if (isset($data['name'])) {
            $role->update(['name' => trim($data['name'])]);
        }

        if ($request->has('permissions')) {
            $role->syncPermissions($this->permissionModels($data['permissions'] ?? []));
        }

        $role->load('permissions');

        return response()->json([
            'message' => 'Role updated successfully.',
            'role'    => $this->formatRole($role, $this->roleUserCount($role)),
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | DELETE /api/admin/roles/{role} — delete only unused, non-system roles
    |--------------------------------------------------------------------------
    */
    public function roleDestroy(Role $role)
    {
        if ($role->name === self::PROTECTED_ROLE) {
            return response()->json([
                'message' => 'The system admin role cannot be deleted.',
            ], 422);
        }

        $userCount = $this->roleUserCount($role);

        if ($userCount > 0) {
            return response()->json([
                'message' => "This role is assigned to {$userCount} user(s). Reassign them before deleting it.",
            ], 422);
        }

        $role->delete();

        return response()->json(['message' => 'Role deleted successfully.']);
    }

    /*
    |--------------------------------------------------------------------------
    | GET /api/admin/permissions — permissions grouped with their roles
    |--------------------------------------------------------------------------
    */
    public function permissionIndex()
    {
        $permissions = Permission::query()
            ->with(['roles:id,name'])
            ->withCount('roles')
            ->orderBy('name')
            ->get()
            ->map(fn (Permission $permission) => $this->formatPermission($permission));

        return response()->json($permissions);
    }

    /*
    |--------------------------------------------------------------------------
    | POST /api/admin/permissions — create a permission
    |--------------------------------------------------------------------------
    */
    public function permissionStore(Request $request)
    {
        $data = $request->validate([
            'name' => [
                'required',
                'string',
                'max:100',
                'regex:/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/',
                Rule::unique('permissions', 'name')->where(
                    fn ($query) => $query->where('guard_name', self::GUARD)
                ),
            ],
        ]);

        $permission = Permission::create([
            'name'       => trim($data['name']),
            'guard_name' => self::GUARD,
        ]);

        $permission->load('roles')->loadCount('roles');

        return response()->json([
            'message'    => 'Permission created successfully.',
            'permission' => $this->formatPermission($permission),
        ], 201);
    }

    /*
    |--------------------------------------------------------------------------
    | PATCH /api/admin/permissions/{permission} — rename a permission
    |--------------------------------------------------------------------------
    */
    public function permissionUpdate(Request $request, Permission $permission)
    {
        $data = $request->validate([
            'name' => [
                'required',
                'string',
                'max:100',
                'regex:/^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/',
                Rule::unique('permissions', 'name')
                    ->ignore($permission->id)
                    ->where(fn ($query) => $query->where('guard_name', self::GUARD)),
            ],
        ]);

        $permission->update(['name' => trim($data['name'])]);
        $permission->load('roles')->loadCount('roles');

        return response()->json([
            'message'    => 'Permission updated successfully.',
            'permission' => $this->formatPermission($permission),
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | DELETE /api/admin/permissions/{permission}
    | -------------------------------------------------------------------------
    | Permissions that are still attached to roles require ?force=1. This avoids
    | silently stripping access from a role after a stray click.
    */
    public function permissionDestroy(Request $request, Permission $permission)
    {
        $roleCount = $permission->roles()->count();

        if ($roleCount > 0 && ! $request->boolean('force')) {
            return response()->json([
                'message' => "This permission is assigned to {$roleCount} role(s). Confirm the deletion to remove it from them.",
            ], 422);
        }

        $permission->delete();

        return response()->json(['message' => 'Permission deleted successfully.']);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private function permissionModels(array $ids)
    {
        return Permission::whereIn('id', $ids)->get();
    }

    /**
     * Spatie's Role::users() relies on the role's guard_name, which is not
     * available when Eloquent builds withCount()/with() on a fresh model.
     * Counting the pivot directly is safe and keeps this endpoint reliable.
     */
    private function roleUserCounts()
    {
        return DB::table(config('permission.table_names.model_has_roles'))
            ->where('model_type', (new User)->getMorphClass())
            ->select('role_id', DB::raw('COUNT(*) as aggregate'))
            ->groupBy('role_id')
            ->pluck('aggregate', 'role_id');
    }

    private function roleUserCount(Role $role): int
    {
        return (int) DB::table(config('permission.table_names.model_has_roles'))
            ->where('model_type', (new User)->getMorphClass())
            ->where('role_id', $role->id)
            ->count();
    }

    private function formatRole(Role $role, int $usersCount = 0): array
    {
        return [
            'id'           => $role->id,
            'name'         => $role->name,
            'guard_name'   => $role->guard_name,
            'users_count'  => $usersCount,
            'permissions'  => $role->permissions
                ->map(fn (Permission $permission) => [
                    'id'   => $permission->id,
                    'name' => $permission->name,
                ])
                ->values(),
            'created_at'   => $role->created_at?->toDateString(),
        ];
    }

    private function formatPermission(Permission $permission): array
    {
        return [
            'id'          => $permission->id,
            'name'        => $permission->name,
            'guard_name'  => $permission->guard_name,
            'roles_count' => (int) ($permission->roles_count ?? 0),
            'roles'       => $permission->roles
                ->map(fn (Role $role) => [
                    'id'   => $role->id,
                    'name' => $role->name,
                ])
                ->values(),
            'created_at'  => $permission->created_at?->toDateString(),
        ];
    }
}
