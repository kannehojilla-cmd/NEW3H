<?php
session_start();
require 'db.php';

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';
    $role     = $_POST['role'] ?? 'user';

    if (!in_array($role, ['user', 'admin'], true)) {
        $role = 'user';
    }

    if ($username === '' || $password === '' || $confirm === '') {
        $error = "Please fill in all fields.";
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters.";
    } elseif (strlen($password) < 6) {
        $error = "Password must be at least 6 characters.";
    } elseif ($password !== $confirm) {
        $error = "Passwords do not match.";
    } else {
        // Check if username is already taken (uses $pdo from db.php)
        $check = $pdo->prepare("SELECT ID FROM Users WHERE UserName = :username");
        $check->execute(['username' => $username]);

        if ($check->fetch()) {
            $error = "That username is already taken.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $insert = $pdo->prepare("INSERT INTO Users (UserName, Password, Role) VALUES (:username, :password, :role)");
            $insert->execute([
                'username' => $username,
                'password' => $hash,
                'role'     => $role
            ]);

            $success = "Account created! You can now log in.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Register</title>
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
    align-items: center;
    justify-content: center;
    padding: 24px;
    font-family: 'Segoe UI', Roboto, sans-serif;
  }

  .panel {
    width: 100%;
    max-width: 400px;
    background: var(--bg-panel);
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 32px 36px 30px;
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

  h2 {
    font-size: 24px;
    font-weight: 600;
    color: var(--text-hi);
    margin: 20px 0 4px;
  }

  p.sub {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    color: var(--text-lo);
    margin: 0 0 26px;
  }

  .error-box {
    font-size: 13px;
    color: #F3AFA8;
    background: rgba(224, 102, 90, 0.1);
    border: 1px solid var(--red-dim);
    border-radius: 3px;
    padding: 10px 12px;
    margin-bottom: 20px;
  }

  .success-box {
    font-size: 13px;
    color: var(--green);
    background: rgba(111, 207, 151, 0.08);
    border: 1px solid var(--green-dim);
    border-radius: 3px;
    padding: 10px 12px;
    margin-bottom: 20px;
  }

  label {
    display: block;
    font-size: 13px;
    color: var(--text-lo);
    margin-bottom: 6px;
  }

  .field {
    margin-bottom: 18px;
  }

  input[type="text"],
  input[type="password"],
  select {
    width: 100%;
    background: var(--bg-deep);
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 11px 12px;
    font-size: 14px;
    color: var(--text-hi);
    outline: none;
    transition: border-color 0.15s ease;
    font-family: inherit;
  }

  input[type="text"]:focus,
  input[type="password"]:focus,
  select:focus {
    border-color: var(--amber);
  }

  button {
    width: 100%;
    margin-top: 6px;
    background: var(--amber);
    color: #201304;
    font-size: 14px;
    font-weight: 600;
    border: none;
    border-radius: 3px;
    padding: 12px;
    cursor: pointer;
    transition: background 0.15s ease;
  }

  button:hover,
  button:focus-visible {
    background: #f0b666;
  }

  .back-link {
    display: block;
    text-align: center;
    margin-top: 18px;
    font-size: 13px;
    color: var(--text-lo);
    text-decoration: none;
  }

  .back-link:hover {
    color: var(--amber);
  }
</style>
</head>
<body>

  <div class="panel">
    <span class="status"><span class="dot"></span>NEW ACCOUNT</span>
    <h2>Create account</h2>
    <p class="sub">register to access the system</p>

    <?php if ($error): ?>
      <div class="error-box"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="success-box"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <form method="POST">
      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <div class="field">
        <label for="confirm_password">Confirm password</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
      </div>
      <div class="field">
        <label for="role">Role</label>
        <select id="role" name="role">
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
      </div>
      <button type="submit">Register</button>
    </form>

    <a class="back-link" href="login.php">Already have an account? Log in</a>
  </div>

</body>
</html>