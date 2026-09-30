<?php
session_start();

// Show the real error message instead of a blank page
ini_set('display_errors', '1');
error_reporting(E_ALL);
set_exception_handler(function ($ex) {
    echo '<pre style="background:#4A2420;color:#F3AFA8;padding:16px;margin:24px;font-family:Consolas,monospace;white-space:pre-wrap;">'
       . 'Database/PHP error: ' . htmlspecialchars($ex->getMessage()) . '</pre>';
});

// ---- Authorization: admins only ----
if (!isset($_SESSION['logged_in']) || ($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    die("Access Denied. You must be an administrator.");
}

require 'db.php';

// ---- Helpers ----
function e($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function redirect($url) { header("Location: $url"); exit(); }
function flash($type, $msg) { $_SESSION['flash'] = ['type' => $type, 'msg' => $msg]; }
function adminCount(PDO $pdo) {
    return (int)$pdo->query("SELECT COUNT(*) FROM Users WHERE role = 'admin'")->fetchColumn();
}

// ---- CSRF token ----
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf'];

$action = $_GET['action'] ?? 'list';
if ($action === 'new') $action = 'create';
$id     = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$errors = [];
$form   = ['username' => '', 'role' => 'user'];

// ---- Handle POST (create / update / delete) ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, $_POST['csrf'] ?? '')) {
        http_response_code(400);
        die("Invalid request token.");
    }

    $op = $_POST['op'] ?? '';

    // ---------- DELETE ----------
    if ($op === 'delete') {
        $delId = (int)($_POST['id'] ?? 0);
        $stmt = $pdo->prepare("SELECT id, username, role FROM Users WHERE id = :id");
        $stmt->execute(['id' => $delId]);
        $target = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$target) {
            flash('error', 'User not found.');
        } elseif ($target['username'] === $_SESSION['username']) {
            flash('error', "You can't delete your own account.");
        } elseif ($target['role'] === 'admin' && adminCount($pdo) <= 1) {
            flash('error', "You can't delete the last administrator.");
        } else {
            $pdo->prepare("DELETE FROM Users WHERE id = :id")->execute(['id' => $delId]);
            flash('success', 'User "' . $target['username'] . '" deleted.');
        }
        redirect('crud.php');
    }

    // ---------- CREATE / UPDATE (shared validation) ----------
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $role     = $_POST['role'] ?? 'user';
    if (!in_array($role, ['user', 'admin'], true)) $role = 'user';

    $form = ['username' => $username, 'role' => $role];
    $isUpdate = ($op === 'update');
    $editId   = (int)($_POST['id'] ?? 0);

    if (strlen($username) < 3) {
        $errors[] = "Username must be at least 3 characters.";
    }

    if (!$isUpdate && strlen($password) < 6) {
        $errors[] = "Password must be at least 6 characters.";
    }
    if ($isUpdate && $password !== '' && strlen($password) < 6) {
        $errors[] = "New password must be at least 6 characters (or leave blank to keep it).";
    }

    // Unique username check
    if (!$errors) {
        $check = $pdo->prepare("SELECT id FROM Users WHERE username = :u AND id <> :id");
        $check->execute(['u' => $username, 'id' => $isUpdate ? $editId : 0]);
        if ($check->fetch()) $errors[] = "That username is already taken.";
    }

    if (!$errors && $op === 'create') {
        $pdo->prepare("INSERT INTO Users (username, password, role) VALUES (:u, :p, :r)")
            ->execute(['u' => $username, 'p' => password_hash($password, PASSWORD_DEFAULT), 'r' => $role]);
        flash('success', 'User "' . $username . '" created.');
        redirect('crud.php');
    }

    if (!$errors && $isUpdate) {
        $stmt = $pdo->prepare("SELECT username, role FROM Users WHERE id = :id");
        $stmt->execute(['id' => $editId]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existing) {
            flash('error', 'User not found.');
            redirect('crud.php');
        }
        if ($existing['role'] === 'admin' && $role !== 'admin' && adminCount($pdo) <= 1) {
            $errors[] = "You can't demote the last administrator.";
        }

        if (!$errors) {
            if ($password !== '') {
                $pdo->prepare("UPDATE Users SET username = :u, role = :r, password = :p WHERE id = :id")
                    ->execute(['u' => $username, 'r' => $role, 'p' => password_hash($password, PASSWORD_DEFAULT), 'id' => $editId]);
            } else {
                $pdo->prepare("UPDATE Users SET username = :u, role = :r WHERE id = :id")
                    ->execute(['u' => $username, 'r' => $role, 'id' => $editId]);
            }

            // Keep the session in sync if the admin edited themselves
            if ($existing['username'] === $_SESSION['username']) {
                $_SESSION['username'] = $username;
                $_SESSION['role']     = $role;
            }

            flash('success', 'User "' . $username . '" updated.');
            redirect('crud.php');
        }
        // fall through to re-show edit form with errors
        $action = 'edit';
        $id = $editId;
    }

    if ($errors && $op === 'create') $action = 'create';
}

// ---- Load data for views ----
$users = [];
$search = trim($_GET['q'] ?? '');

if ($action === 'edit') {
    $stmt = $pdo->prepare("SELECT id, username, role FROM Users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        flash('error', 'User not found.');
        redirect('crud.php');
    }
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $form = ['username' => $row['username'], 'role' => $row['role']];
    }
} elseif ($action === 'list') {
    if ($search !== '') {
        $stmt = $pdo->prepare("SELECT id, username, role FROM Users WHERE username LIKE :q ORDER BY id ASC");
        $stmt->execute(['q' => '%' . $search . '%']);
    } else {
        $stmt = $pdo->query("SELECT id, username, role FROM Users ORDER BY id ASC");
    }
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Manage Users</title>
<style>
  :root {
    --bg-deep:    #0A0E17;
    --bg-panel:   #10151F;
    --line:       #1E2634;
    --amber:      #E8A54B;
    --amber-dim:  #6B5230;
    --red:        #E0665A;
    --red-dim:    #4A2420;
    --green:      #6FCF97;
    --green-dim:  #234A38;
    --text-hi:    #E7E9EC;
    --text-lo:    #7C8598;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    background-color: var(--bg-deep);
    background-image:
      linear-gradient(var(--line) 1px, transparent 1px),
      linear-gradient(90deg, var(--line) 1px, transparent 1px);
    background-size: 40px 40px;
    display: flex; align-items: flex-start; justify-content: center;
    padding: 40px 24px;
    font-family: 'Segoe UI', Roboto, sans-serif;
  }
  .panel {
    width: 100%; max-width: 760px;
    background: var(--bg-panel);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 32px 36px 28px;
    position: relative;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .panel::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0;
    height: 3px; background: var(--amber); border-radius: 4px 4px 0 0;
  }
  .status {
    display: inline-flex; align-items: center; gap: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px; letter-spacing: 0.06em;
    color: var(--amber);
    background: rgba(232,165,75,0.08);
    border: 1px solid var(--amber-dim);
    padding: 5px 10px; border-radius: 3px;
  }
  .status .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--amber); box-shadow: 0 0 6px var(--amber); }
  h1 { font-size: 26px; font-weight: 600; color: var(--text-hi); margin: 20px 0 6px; }
  h1 span { color: var(--amber); }
  p.sub { font-family: 'Consolas', monospace; font-size: 13px; color: var(--text-lo); margin: 0 0 24px; }

  .flash { font-size: 13px; border-radius: 3px; padding: 10px 12px; margin-bottom: 18px; }
  .flash.success { color: var(--green); background: rgba(111,207,151,0.08); border: 1px solid var(--green-dim); }
  .flash.error   { color: #F3AFA8; background: rgba(224,102,90,0.1); border: 1px solid var(--red-dim); }
  .flash ul { margin: 0; padding-left: 18px; }

  .toolbar { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
  .toolbar form { display: flex; gap: 8px; flex: 1; min-width: 200px; }
  .toolbar input[type="text"] { flex: 1; }

  .btn {
    display: inline-block; font-size: 13px; font-weight: 600; font-family: inherit;
    color: var(--text-hi); text-decoration: none; cursor: pointer;
    background: transparent; border: 1px solid var(--line);
    padding: 9px 16px; border-radius: 3px;
    transition: border-color .15s, color .15s, background .15s;
  }
  .btn:hover, .btn:focus-visible { border-color: var(--amber); color: var(--amber); }
  .btn.primary { background: var(--amber); color: #201304; border-color: var(--amber); }
  .btn.primary:hover { background: #f0b666; color: #201304; }
  .btn.danger:hover { border-color: var(--red); color: var(--red); }
  .btn.small { padding: 5px 10px; font-size: 12px; }

  .table-wrap { border: 1px solid var(--line); border-radius: 4px; overflow-x: auto; margin-bottom: 24px; }
  table.users { width: 100%; border-collapse: collapse; font-size: 14px; }
  table.users th, table.users td { text-align: left; padding: 10px 14px; }
  table.users thead th {
    font-family: 'Consolas', monospace; font-size: 11px; letter-spacing: .06em;
    text-transform: uppercase; color: var(--text-lo);
    background: rgba(124,133,152,0.06); border-bottom: 1px solid var(--line);
  }
  table.users tbody tr { border-bottom: 1px solid var(--line); }
  table.users tbody tr:last-child { border-bottom: none; }
  table.users td { color: var(--text-hi); }
  td.actions { white-space: nowrap; text-align: right; }
  td.actions form { display: inline; }
  .you { color: var(--text-lo); font-size: 12px; margin-left: 6px; }

  .role-badge { display: inline-block; font-family: 'Consolas', monospace; font-size: 11px; padding: 2px 8px; border-radius: 3px; }
  .role-badge.admin { color: var(--amber); background: rgba(232,165,75,0.1); border: 1px solid var(--amber-dim); }
  .role-badge.user  { color: var(--text-lo); background: rgba(124,133,152,0.08); border: 1px solid var(--line); }
  .empty td { color: var(--text-lo); text-align: center; padding: 18px 14px; }

  label { display: block; font-size: 13px; color: var(--text-lo); margin-bottom: 6px; }
  .field { margin-bottom: 18px; }
  .hint { font-size: 12px; color: var(--text-lo); margin-top: 5px; }
  input[type="text"], input[type="password"], select {
    width: 100%; background: var(--bg-deep); border: 1px solid var(--line);
    border-radius: 3px; padding: 11px 12px; font-size: 14px; font-family: inherit;
    color: var(--text-hi); outline: none; transition: border-color .15s;
  }
  input:focus, select:focus { border-color: var(--amber); }
  .form-actions { display: flex; gap: 10px; margin-top: 8px; }
  .nav { display: flex; gap: 10px; margin-top: 8px; }
</style>
</head>
<body>
<div class="panel">
  <span class="status"><span class="dot"></span>AUTHORIZED SESSION</span>
  <h1>Manage <span>users</span></h1>
  <p class="sub">create · read · update · delete</p>

  <?php if ($flash): ?>
    <div class="flash <?php echo e($flash['type']); ?>"><?php echo e($flash['msg']); ?></div>
  <?php endif; ?>

  <?php if ($errors): ?>
    <div class="flash error"><ul>
      <?php foreach ($errors as $err): ?><li><?php echo e($err); ?></li><?php endforeach; ?>
    </ul></div>
  <?php endif; ?>

  <?php if ($action === 'create' || $action === 'edit'): ?>
    <!-- ================= CREATE / EDIT FORM ================= -->
    <?php $isEdit = ($action === 'edit'); ?>
    <form method="POST" action="crud.php?action=<?php echo $isEdit ? 'edit&id=' . (int)$id : 'create'; ?>">
      <input type="hidden" name="csrf" value="<?php echo e($csrf); ?>">
      <input type="hidden" name="op" value="<?php echo $isEdit ? 'update' : 'create'; ?>">
      <?php if ($isEdit): ?><input type="hidden" name="id" value="<?php echo (int)$id; ?>"><?php endif; ?>

      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" value="<?php echo e($form['username']); ?>" required autofocus>
      </div>
      <div class="field">
        <label for="password"><?php echo $isEdit ? 'New password' : 'Password'; ?></label>
        <input type="password" id="password" name="password" <?php echo $isEdit ? '' : 'required'; ?> autocomplete="new-password">
        <?php if ($isEdit): ?><div class="hint">Leave blank to keep the current password.</div><?php endif; ?>
      </div>
      <div class="field">
        <label for="role">Role</label>
        <select id="role" name="role">
          <option value="user"  <?php echo $form['role'] === 'user'  ? 'selected' : ''; ?>>User</option>
          <option value="admin" <?php echo $form['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
        </select>
      </div>
      <div class="form-actions">
        <button type="submit" class="btn primary"><?php echo $isEdit ? 'Save changes' : 'Create user'; ?></button>
        <a class="btn" href="crud.php">Cancel</a>
      </div>
    </form>

  <?php else: ?>
    <!-- ================= LIST ================= -->
    <div class="toolbar">
      <form method="GET" action="crud.php">
        <input type="text" name="q" placeholder="Search username…" value="<?php echo e($search); ?>">
        <button type="submit" class="btn">Search</button>
        <?php if ($search !== ''): ?><a class="btn" href="crud.php">Clear</a><?php endif; ?>
      </form>
      <a class="btn primary" href="crud.php?action=create">+ New user</a>
    </div>

    <div class="table-wrap">
      <table class="users">
        <thead>
          <tr><th>ID</th><th>Username</th><th>Role</th><th></th></tr>
        </thead>
        <tbody>
          <?php if (empty($users)): ?>
            <tr class="empty"><td colspan="4">No users found.</td></tr>
          <?php else: foreach ($users as $u): ?>
            <tr>
              <td><?php echo (int)$u['id']; ?></td>
              <td>
                <?php echo e($u['username']); ?>
                <?php if ($u['username'] === $_SESSION['username']): ?><span class="you">(you)</span><?php endif; ?>
              </td>
              <td><span class="role-badge <?php echo e($u['role']); ?>"><?php echo e($u['role']); ?></span></td>
              <td class="actions">
                <a class="btn small" href="crud.php?action=edit&id=<?php echo (int)$u['id']; ?>">Edit</a>
                <?php if ($u['username'] !== $_SESSION['username']): ?>
                  <form method="POST" action="crud.php"
                        onsubmit="return confirm('Delete user <?php echo e(addslashes($u['username'])); ?>? This cannot be undone.');">
                    <input type="hidden" name="csrf" value="<?php echo e($csrf); ?>">
                    <input type="hidden" name="op" value="delete">
                    <input type="hidden" name="id" value="<?php echo (int)$u['id']; ?>">
                    <button type="submit" class="btn small danger">Delete</button>
                  </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; endif; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>

  <div class="nav">
    <a class="btn" href="admin.php">← Admin home</a>
    <a class="btn" href="logout.php">Log out</a>
  </div>
</div>
</body>
</html>