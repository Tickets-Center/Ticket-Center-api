<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Sanctum\Sanctum;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

uses(RefreshDatabase::class);

beforeEach(function () {
    Role::create(['name' => 'admin', 'guard_name' => 'web']);

    $this->admin = User::factory()->create();
    $this->admin->assignRole('admin');

    Sanctum::actingAs($this->admin);
});

it('returns roles with their permissions and user counts', function () {
    $manager = Role::create(['name' => 'manager', 'guard_name' => 'web']);
    $permission = Permission::create(['name' => 'tickets.view', 'guard_name' => 'web']);
    $manager->givePermissionTo($permission);

    $this->getJson('/api/admin/roles/manage')
        ->assertOk()
        ->assertJsonFragment([
            'name'        => 'manager',
            'users_count' => 0,
        ])
        ->assertJsonFragment([
            'name' => 'tickets.view',
        ]);
});

it('creates a role and syncs its permissions', function () {
    $view = Permission::create(['name' => 'tickets.view', 'guard_name' => 'web']);
    $create = Permission::create(['name' => 'tickets.create', 'guard_name' => 'web']);

    $this->postJson('/api/admin/roles', [
        'name'        => 'support',
        'permissions' => [$view->id, $create->id],
    ])
        ->assertCreated()
        ->assertJsonPath('role.name', 'support');

    $role = Role::findByName('support', 'web');

    expect($role->permissions)->toHaveCount(2)
        ->and($role->hasPermissionTo('tickets.view'))->toBeTrue();
});

it('updates a role and replaces its permissions', function () {
    $role = Role::create(['name' => 'support', 'guard_name' => 'web']);
    $view = Permission::create(['name' => 'tickets.view', 'guard_name' => 'web']);
    $delete = Permission::create(['name' => 'tickets.delete', 'guard_name' => 'web']);
    $role->givePermissionTo($view);

    $this->patchJson("/api/admin/roles/{$role->id}", [
        'name'        => 'support-agent',
        'permissions' => [$delete->id],
    ])
        ->assertOk()
        ->assertJsonPath('role.name', 'support-agent');

    $role->refresh();

    expect($role->hasPermissionTo('tickets.delete'))->toBeTrue()
        ->and($role->hasPermissionTo('tickets.view'))->toBeFalse();
});

it('protects the system admin role from rename and deletion', function () {
    $admin = Role::findByName('admin', 'web');

    $this->patchJson("/api/admin/roles/{$admin->id}", ['name' => 'super-admin'])
        ->assertStatus(422);

    $this->deleteJson("/api/admin/roles/{$admin->id}")
        ->assertStatus(422);

    expect(Role::where('name', 'admin')->exists())->toBeTrue();
});

it('refuses to delete a role that is still assigned to users', function () {
    $role = Role::create(['name' => 'employee', 'guard_name' => 'web']);
    User::factory()->create()->assignRole($role);

    $this->deleteJson("/api/admin/roles/{$role->id}")
        ->assertStatus(422);

    expect(Role::where('name', 'employee')->exists())->toBeTrue();
});

it('creates, renames and safely deletes permissions', function () {
    $this->postJson('/api/admin/permissions', ['name' => 'reports.view'])
        ->assertCreated()
        ->assertJsonPath('permission.name', 'reports.view');

    $permission = Permission::findByName('reports.view', 'web');
    $role = Role::create(['name' => 'manager', 'guard_name' => 'web']);
    $role->givePermissionTo($permission);

    $this->patchJson("/api/admin/permissions/{$permission->id}", ['name' => 'reports.export'])
        ->assertOk()
        ->assertJsonPath('permission.name', 'reports.export');

    $this->deleteJson("/api/admin/permissions/{$permission->id}")
        ->assertStatus(422);

    $this->deleteJson("/api/admin/permissions/{$permission->id}?force=1")
        ->assertOk();

    expect(Permission::where('name', 'reports.export')->exists())->toBeFalse();
});

it('blocks non-admin users from access management', function () {
    $employee = User::factory()->create();
    $employee->assignRole(Role::create(['name' => 'employee', 'guard_name' => 'web']));

    Sanctum::actingAs($employee);

    $this->getJson('/api/admin/roles/manage')->assertForbidden();
});
