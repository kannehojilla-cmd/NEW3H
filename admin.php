<?php
session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['role'] !== 'admin') {
    die("Access Denied. You must be an administrator.");
}

require 'db.php';

$stmt = $pdo->query("SELECT id, username, role FROM Users ORDER BY id ASC");
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Area</title>
<style>
  :root {
    --bg-deep:    #0A0E17;
    --bg-panel:   #10151F;
    --line:       #1E2634;
    --amber:      #E8A54B;
    --amber-dim:  #6B5230;
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
    align-items: center;
    justify-content: center;
    padding: 24px;
    font-family: 'Segoe UI', Roboto, sans-serif;
  }

  .panel {
    width: 100%;
    max-width: 720px;
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
    background: var(--amber);
    border-radius: 4px 4px 0 0;
  }

  .status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    letter-spacing: 0.06em;
    color: var(--amber);
    background: rgba(232, 165, 75, 0.08);
    border: 1px solid var(--amber-dim);
    padding: 5px 10px;
    border-radius: 3px;
  }

  .status .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--amber);
    box-shadow: 0 0 6px var(--amber);
  }

  h1 {
    font-size: 26px;
    font-weight: 600;
    color: var(--text-hi);
    margin: 20px 0 6px;
    line-height: 1.3;
  }

  h1 span {
    color: var(--amber);
    font-weight: 700;
  }

  p.sub {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    color: var(--text-lo);
    margin: 0 0 28px;
  }

  a.logout {
    display: inline-block;
    font-size: 14px;
    color: var(--text-hi);
    text-decoration: none;
    border: 1px solid var(--line);
    padding: 10px 18px;
    border-radius: 3px;
    transition: border-color 0.15s ease, color 0.15s ease;
  }

  a.logout:hover,
  a.logout:focus-visible {
    border-color: var(--amber);
    color: var(--amber);
  }

  h2.section {
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--text-lo);
    margin: 8px 0 12px;
  }

  .table-wrap {
    border: 1px solid var(--line);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 28px;
  }

  table.users {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }

  table.users th,
  table.users td {
    text-align: left;
    padding: 10px 14px;
  }

  table.users thead th {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-lo);
    background: rgba(124, 133, 152, 0.06);
    border-bottom: 1px solid var(--line);
  }

  table.users tbody tr {
    border-bottom: 1px solid var(--line);
  }

  table.users tbody tr:last-child {
    border-bottom: none;
  }

  table.users td {
    color: var(--text-hi);
  }

  .role-badge {
    display: inline-block;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    letter-spacing: 0.04em;
    padding: 2px 8px;
    border-radius: 3px;
  }

  .role-badge.admin {
    color: var(--amber);
    background: rgba(232, 165, 75, 0.1);
    border: 1px solid var(--amber-dim);
  }

  .role-badge.user {
    color: var(--text-lo);
    background: rgba(124, 133, 152, 0.08);
    border: 1px solid var(--line);
  }

  .empty-row td {
    color: var(--text-lo);
    text-align: center;
    padding: 18px 14px;
  }
</style>
<style>
  .crud-links { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
  a.crud-btn {
    display: inline-block;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-hi);
    text-decoration: none;
    border: 1px solid var(--line);
    padding: 10px 18px;
    border-radius: 3px;
    transition: border-color 0.15s ease, color 0.15s ease;
  }
  a.crud-btn:hover, a.crud-btn:focus-visible { border-color: var(--amber); color: var(--amber); }
  a.crud-btn.primary { background: var(--amber); color: #201304; border-color: var(--amber); }
  a.crud-btn.primary:hover { background: #f0b666; color: #201304; }
</style>
</head>
<body>

  <div class="panel">
    <span class="status"><span class="dot"></span>AUTHORIZED SESSION</span>
    <h1>Welcome back, <span><?php echo htmlspecialchars($_SESSION['username']); ?></span></h1>
    <p class="sub">role: administrator · access level: full</p>

    <h2 class="section">Users (<?php echo count($users); ?>)</h2>
    <div class="table-wrap">
      <table class="users">
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($users)): ?>
            <tr class="empty-row"><td colspan="3">No users found.</td></tr>
          <?php else: ?>
            <?php foreach ($users as $u): ?>
              <tr>
                <td><?php echo htmlspecialchars($u['id']); ?></td>
                <td><?php echo htmlspecialchars($u['username']); ?></td>
                <td>
                  <span class="role-badge <?php echo htmlspecialchars($u['role']); ?>">
                    <?php echo htmlspecialchars($u['role']); ?>
                  </span>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>

    <div class="crud-links">
      <a class="crud-btn primary" href="crud.php">Manage users</a>
      <a class="crud-btn" href="crud.php?action=create">+ New user</a>
    </div>

    <a class="logout" href="logout.php">Log out</a>
  </div>

</body>
</html>