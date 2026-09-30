<?php
session_start();

// Security guard: must be logged in
if (!isset($_SESSION['logged_in'])) {
    header("Location: login.php");
    exit();
}

require 'db.php';

// The session stores the username, but tasks.user_id needs the numeric id.
if (empty($_SESSION['user_id'])) {
    $s = $pdo->prepare("SELECT id FROM Users WHERE username = :u");
    $s->execute(['u' => $_SESSION['username']]);
    $row = $s->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        session_destroy();
        header("Location: login.php");
        exit();
    }
    $_SESSION['user_id'] = (int)$row['id'];
}
$userId = (int)$_SESSION['user_id'];

// CSRF token
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$error = "";
$flash = $_SESSION['flash'] ?? "";
unset($_SESSION['flash']);

/* ---------- POST actions: create / update / delete / toggle ---------- */
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        http_response_code(403);
        die("Invalid request token.");
    }

    $action = $_POST['action'] ?? '';
    $id     = (int)($_POST['id'] ?? 0);

    if ($action === 'save') {
        $title  = trim($_POST['title'] ?? '');
        $desc   = trim($_POST['description'] ?? '');
        $status = $_POST['status'] ?? 'pending';
        if (!in_array($status, ['pending', 'completed'], true)) {
            $status = 'pending';
        }

        if ($title === '') {
            $error = "Title is required.";
        } elseif (mb_strlen($title) > 255) {
            $error = "Title must be 255 characters or fewer.";
        } else {
            if ($id > 0) {
                $stmt = $pdo->prepare(
                    "UPDATE tasks SET title = :t, description = :d, status = :s
                     WHERE id = :id AND user_id = :uid"
                );
                $stmt->execute(['t' => $title, 'd' => $desc, 's' => $status, 'id' => $id, 'uid' => $userId]);
                $_SESSION['flash'] = "Task updated.";
            } else {
                $stmt = $pdo->prepare(
                    "INSERT INTO tasks (user_id, title, description, status)
                     VALUES (:uid, :t, :d, :s)"
                );
                $stmt->execute(['uid' => $userId, 't' => $title, 'd' => $desc, 's' => $status]);
                $_SESSION['flash'] = "Task created.";
            }
            header("Location: user_crud.php");
            exit();
        }
        // On validation error, fall through and redisplay the form
        $_GET['action'] = $id > 0 ? 'edit' : 'create';
        $_GET['id'] = $id;
        $formData = ['id' => $id, 'title' => $title, 'description' => $desc, 'status' => $status];

    } elseif ($action === 'delete' && $id > 0) {
        $stmt = $pdo->prepare("DELETE FROM tasks WHERE id = :id AND user_id = :uid");
        $stmt->execute(['id' => $id, 'uid' => $userId]);
        $_SESSION['flash'] = "Task deleted.";
        header("Location: user_crud.php");
        exit();

    } elseif ($action === 'toggle' && $id > 0) {
        $stmt = $pdo->prepare(
            "UPDATE tasks
             SET status = IF(status = 'pending', 'completed', 'pending')
             WHERE id = :id AND user_id = :uid"
        );
        $stmt->execute(['id' => $id, 'uid' => $userId]);
        header("Location: user_crud.php");
        exit();
    }
}

/* ---------- Decide which view to show ---------- */
$view = $_GET['action'] ?? 'list';
$formData = $formData ?? ['id' => 0, 'title' => '', 'description' => '', 'status' => 'pending'];

if ($view === 'edit') {
    if (!isset($formData['id']) || $formData['id'] == 0 || $_SERVER["REQUEST_METHOD"] !== "POST") {
        $stmt = $pdo->prepare("SELECT * FROM tasks WHERE id = :id AND user_id = :uid");
        $stmt->execute(['id' => (int)($_GET['id'] ?? 0), 'uid' => $userId]);
        $found = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$found) {
            $_SESSION['flash'] = "Task not found.";
            header("Location: user_crud.php");
            exit();
        }
        $formData = $found;
    }
} elseif ($view !== 'create') {
    $view = 'list';
}

$tasks = [];
if ($view === 'list') {
    $stmt = $pdo->prepare("SELECT * FROM tasks WHERE user_id = :uid ORDER BY status ASC, created_at DESC");
    $stmt->execute(['uid' => $userId]);
    $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function e($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Tasks</title>
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
    margin: 0;
    min-height: 100vh;
    background-color: var(--bg-deep);
    background-image:
      linear-gradient(var(--line) 1px, transparent 1px),
      linear-gradient(90deg, var(--line) 1px, transparent 1px);
    background-size: 40px 40px;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 24px;
    font-family: 'Segoe UI', Roboto, sans-serif;
  }

  .panel {
    width: 100%;
    max-width: 720px;
    margin: 24px 0;
    background: var(--bg-panel);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 32px 36px 28px;
    position: relative;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }

  .panel::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--text-lo);
    border-radius: 4px 4px 0 0;
  }

  .status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    letter-spacing: 0.06em;
    color: var(--text-lo);
    background: rgba(124, 133, 152, 0.08);
    border: 1px solid var(--line);
    padding: 5px 10px;
    border-radius: 3px;
  }

  .status .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-lo); }

  h1 { font-size: 26px; font-weight: 600; color: var(--text-hi); margin: 20px 0 6px; }

  p.sub {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    color: var(--text-lo);
    margin: 0 0 24px;
  }

  .flash, .error-box {
    font-size: 13px;
    border-radius: 3px;
    padding: 10px 12px;
    margin-bottom: 20px;
  }
  .flash { color: var(--green); background: rgba(111,207,151,0.08); border: 1px solid var(--green-dim); }
  .error-box { color: #F3AFA8; background: rgba(224,102,90,0.1); border: 1px solid var(--red-dim); }

  .btn {
    display: inline-block;
    font-family: inherit;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-hi);
    text-decoration: none;
    background: transparent;
    border: 1px solid var(--line);
    padding: 10px 18px;
    border-radius: 3px;
    cursor: pointer;
    transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
  }
  .btn:hover, .btn:focus-visible { border-color: var(--amber); color: var(--amber); }
  .btn.primary { background: var(--amber); color: #201304; border-color: var(--amber); }
  .btn.primary:hover { background: #f0b666; color: #201304; }
  .btn.danger:hover { border-color: var(--red); color: var(--red); }
  .btn.small { font-size: 12px; padding: 5px 10px; font-weight: 500; }

  .toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }

  .task-list { list-style: none; margin: 0 0 24px; padding: 0; border: 1px solid var(--line); border-radius: 4px; }
  .task { padding: 14px 16px; border-bottom: 1px solid var(--line); display: flex; gap: 14px; align-items: flex-start; justify-content: space-between; }
  .task:last-child { border-bottom: none; }
  .task-main { min-width: 0; flex: 1; }
  .task-title { color: var(--text-hi); font-size: 15px; font-weight: 600; margin: 0 0 4px; word-wrap: break-word; }
  .task.done .task-title { text-decoration: line-through; color: var(--text-lo); }
  .task-desc { color: var(--text-lo); font-size: 13px; margin: 0 0 6px; white-space: pre-wrap; word-wrap: break-word; }
  .task-meta { font-family: 'Consolas', 'Courier New', monospace; font-size: 11px; color: var(--text-lo); }
  .task-actions { display: flex; gap: 6px; flex-shrink: 0; flex-wrap: wrap; justify-content: flex-end; }
  .task-actions form { margin: 0; }

  .badge {
    display: inline-block;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 3px;
    margin-right: 8px;
  }
  .badge.pending { color: var(--amber); background: rgba(232,165,75,0.1); border: 1px solid var(--amber-dim); }
  .badge.completed { color: var(--green); background: rgba(111,207,151,0.08); border: 1px solid var(--green-dim); }

  .empty { color: var(--text-lo); text-align: center; padding: 28px 14px; border: 1px dashed var(--line); border-radius: 4px; margin-bottom: 24px; }

  label { display: block; font-size: 13px; color: var(--text-lo); margin-bottom: 6px; }
  .field { margin-bottom: 18px; }

  input[type="text"], textarea, select {
    width: 100%;
    background: var(--bg-deep);
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 11px 12px;
    font-size: 14px;
    font-family: inherit;
    color: var(--text-hi);
    outline: none;
    transition: border-color 0.15s ease;
  }
  textarea { min-height: 110px; resize: vertical; }
  input:focus, textarea:focus, select:focus { border-color: var(--amber); }

  .form-actions { display: flex; gap: 10px; }

  @media (max-width: 520px) {
    .panel { padding: 24px 20px; }
    .task { flex-direction: column; }
    .task-actions { justify-content: flex-start; }
  }
</style>
</head>
<body>

  <div class="panel">
    <span class="status"><span class="dot"></span>TASK MANAGER</span>

    <?php if ($view === 'list'): ?>

      <h1>My tasks</h1>
      <p class="sub">signed in as <?php echo e($_SESSION['username']); ?> · <?php echo count($tasks); ?> task(s)</p>

      <?php if ($flash): ?><div class="flash"><?php echo e($flash); ?></div><?php endif; ?>

      <div class="toolbar">
        <a class="btn primary" href="user_crud.php?action=create">+ New task</a>
        <a class="btn" href="user.php">← Back</a>
      </div>

      <?php if (empty($tasks)): ?>
        <div class="empty">You have no tasks yet. Create your first one!</div>
      <?php else: ?>
        <ul class="task-list">
          <?php foreach ($tasks as $t): ?>
            <li class="task <?php echo $t['status'] === 'completed' ? 'done' : ''; ?>">
              <div class="task-main">
                <p class="task-title"><?php echo e($t['title']); ?></p>
                <?php if (!empty($t['description'])): ?>
                  <p class="task-desc"><?php echo e($t['description']); ?></p>
                <?php endif; ?>
                <div class="task-meta">
                  <span class="badge <?php echo e($t['status']); ?>"><?php echo e($t['status']); ?></span>
                  created <?php echo e($t['created_at']); ?>
                </div>
              </div>
              <div class="task-actions">
                <form method="POST">
                  <input type="hidden" name="csrf" value="<?php echo e($_SESSION['csrf']); ?>">
                  <input type="hidden" name="action" value="toggle">
                  <input type="hidden" name="id" value="<?php echo (int)$t['id']; ?>">
                  <button class="btn small" type="submit">
                    <?php echo $t['status'] === 'pending' ? 'Mark done' : 'Reopen'; ?>
                  </button>
                </form>
                <a class="btn small" href="user_crud.php?action=edit&id=<?php echo (int)$t['id']; ?>">Edit</a>
                <form method="POST" onsubmit="return confirm('Delete this task?');">
                  <input type="hidden" name="csrf" value="<?php echo e($_SESSION['csrf']); ?>">
                  <input type="hidden" name="action" value="delete">
                  <input type="hidden" name="id" value="<?php echo (int)$t['id']; ?>">
                  <button class="btn small danger" type="submit">Delete</button>
                </form>
              </div>
            </li>
          <?php endforeach; ?>
        </ul>
      <?php endif; ?>

    <?php else: ?>

      <h1><?php echo $view === 'edit' ? 'Edit task' : 'New task'; ?></h1>
      <p class="sub"><?php echo $view === 'edit' ? 'update the details below' : 'fill in the details below'; ?></p>

      <?php if ($error): ?><div class="error-box"><?php echo e($error); ?></div><?php endif; ?>

      <form method="POST">
        <input type="hidden" name="csrf" value="<?php echo e($_SESSION['csrf']); ?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="<?php echo (int)$formData['id']; ?>">

        <div class="field">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" maxlength="255" required autofocus
                 value="<?php echo e($formData['title']); ?>">
        </div>
        <div class="field">
          <label for="description">Description (optional)</label>
          <textarea id="description" name="description"><?php echo e($formData['description']); ?></textarea>
        </div>
        <div class="field">
          <label for="status">Status</label>
          <select id="status" name="status">
            <option value="pending"   <?php echo $formData['status'] === 'pending' ? 'selected' : ''; ?>>Pending</option>
            <option value="completed" <?php echo $formData['status'] === 'completed' ? 'selected' : ''; ?>>Completed</option>
          </select>
        </div>

        <div class="form-actions">
          <button class="btn primary" type="submit"><?php echo $view === 'edit' ? 'Save changes' : 'Create task'; ?></button>
          <a class="btn" href="user_crud.php">Cancel</a>
        </div>
      </form>

    <?php endif; ?>
  </div>

</body>
</html>