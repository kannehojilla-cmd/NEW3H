<?php
session_start();

// Security Guard: Just check for the wristband
if (!isset($_SESSION['logged_in'])) {
    header("Location: login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>User Area</title>
<style>
  :root {
    --bg-deep:  #0A0E17;
    --bg-panel: #10151F;
    --line:     #1E2634;
    --amber:    #E8A54B;
    --text-hi:  #E7E9EC;
    --text-lo:  #7C8598;
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
    max-width: 480px;
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

  .status .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--text-lo);
  }

  h1 {
    font-size: 26px;
    font-weight: 600;
    color: var(--text-hi);
    margin: 20px 0 6px;
    line-height: 1.3;
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
</style>
</head>
<body>

  <div class="panel">
    <span class="status"><span class="dot"></span>SESSION ACTIVE</span>
    <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
    <p class="sub">role: user · access level: standard</p>
    <a class="logout" href="user_crud.php" style="margin-right:10px;">My tasks</a>
    <a class="logout" href="logout.php">Log out</a>
  </div>

</body>
</html>