<?php
session_start(); // Must be the very first line!
require 'db.php';

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        $error = "Please enter both username and password.";
    } else {
        // 1. Fetch user safely using PDO
        $stmt = $pdo->prepare("SELECT * FROM Users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        $authenticated = false;

        if ($user) {
            if (password_verify($password, $user['password'])) {
                // Normal case: password column already holds a proper bcrypt hash
                $authenticated = true;
            } elseif (trim($password) === trim($user['password'])) {
                // Legacy case: this row still has a plaintext password.
                // It matches, so log in AND upgrade the row to a real hash.
                $authenticated = true;
                $newHash = password_hash(trim($password), PASSWORD_DEFAULT);
                $update = $pdo->prepare("UPDATE Users SET password = :hash WHERE id = :id");
                $update->execute(['hash' => $newHash, 'id' => $user['id']]);
            }
        }

        // TEMPORARY DEBUG — remove once login works
        if ($user && !$authenticated) {
            echo "<pre>";
            echo "Typed password:  [" . $password . "]\n";
            echo "Stored password: [" . $user['password'] . "]\n";
            echo "Match (strict): " . var_export($password === $user['password'], true) . "\n";
            echo "Match (trimmed): " . var_export(trim($password) === trim($user['password']), true) . "\n";
            echo "</pre>";
            exit();
        }
        // END TEMPORARY DEBUG

        if ($authenticated) {
            session_regenerate_id(true); // prevent session fixation

            $role = strtolower(trim($user['role']));

            $_SESSION['logged_in'] = true;
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $role; // Crucial for authorization!

            // 2. The Traffic Cop (Redirection)
            if ($role === 'admin') {
                header("Location: admin.php");
                exit();
            } else {
                header("Location: user.php");
                exit();
            }
        } else {
            $error = "Invalid username or password!";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>System Login</title>
<style>
  :root {
    --bg-deep:    #0A0E17;
    --bg-panel:   #10151F;
    --line:       #1E2634;
    --amber:      #E8A54B;
    --amber-dim:  #6B5230;
    --red:        #E0665A;
    --red-dim:    #4A2420;
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
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 13px;
    color: #F3AFA8;
    background: rgba(224, 102, 90, 0.1);
    border: 1px solid var(--red-dim);
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
  input[type="password"] {
    width: 100%;
    background: var(--bg-deep);
    border: 1px solid var(--line);
    border-radius: 3px;
    padding: 11px 12px;
    font-size: 14px;
    color: var(--text-hi);
    outline: none;
    transition: border-color 0.15s ease;
  }

  input[type="text"]:focus,
  input[type="password"]:focus {
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
    <span class="status"><span class="dot"></span>AUTHENTICATION REQUIRED</span>
    <h2>System login</h2>
    <p class="sub">enter your credentials to continue</p>

    <?php if ($error): ?>
      <div class="error-box"><?php echo htmlspecialchars($error); ?></div>
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
      <button type="submit">Log in</button>
    </form>

    <a class="back-link" href="register.php">Create a new account</a>
  </div>

</body>
</html>