<?php
require_once(__DIR__ . "/../../partials/nav.php");
is_logged_in(true);
?>
<?php
if (isset($_POST["save"])) {
    $email = se($_POST, "email", null, false);
    $username = se($_POST, "username", null, false);
    $hasError = false;
    //sanitize
    $email = sanitize_email($email);
    //validate
    if (!is_valid_email($email)) {
        flash("Invalid email address", "danger");
        $hasError = true;
    }
    if (!is_valid_username($username)) {
        flash("Username must only contain 3-16 characters a-z, 0-9, _, or -", "danger");
        $hasError = true;
    }
    if (!$hasError) {
        $params = [":email" => $email, ":username" => $username, ":id" => get_user_id()];
        $db = getDB();
        $stmt = $db->prepare("UPDATE Users set email = :email, username = :username where id = :id");
        try {
            $stmt->execute($params);
            flash("Profile saved", "success");
        } catch (PDOException $e) {
            users_check_duplicate($e->errorInfo);
        }
        //select fresh data from table
        $stmt = $db->prepare("SELECT id, email, username from Users where id = :id LIMIT 1");
        try {
            $stmt->execute([":id" => get_user_id()]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                //$_SESSION["user"] = $user;
                $_SESSION["user"]["email"] = $user["email"];
                $_SESSION["user"]["username"] = $user["username"];
            } else {
                flash("User doesn't exist", "danger");
            }
        } catch (Exception $e) {
            flash("An unexpected error occurred, please try again", "danger");
            //echo "<pre>" . var_export($e->errorInfo, true) . "</pre>";
        }
    }


    //check/update password
    $current_password = se($_POST, "currentPassword", null, false);
    $new_password = se($_POST, "newPassword", null, false);
    $confirm_password = se($_POST, "confirmPassword", null, false);
    if (!empty($current_password) && !empty($new_password) && !empty($confirm_password)) {
        $hasError = false;
        if (!is_valid_password($new_password)) {
            flash("Password too short", "danger");
            $hasError = true;
        }
        if (!$hasError) {
            if ($new_password === $confirm_password) {
                //TODO validate current
                $stmt = $db->prepare("SELECT password from Users where id = :id");
                try {
                    $stmt->execute([":id" => get_user_id()]);
                    $result = $stmt->fetch(PDO::FETCH_ASSOC);
                    if (isset($result["password"])) {
                        if (password_verify($current_password, $result["password"])) {
                            $query = "UPDATE Users set password = :password where id = :id";
                            $stmt = $db->prepare($query);
                            $stmt->execute([
                                ":id" => get_user_id(),
                                ":password" => password_hash($new_password, PASSWORD_BCRYPT)
                            ]);

                            flash("Password reset", "success");
                        } else {
                            flash("Current password is invalid", "warning");
                        }
                    }
                } catch (PDOException $e) {
                    echo "<pre>" . var_export($e->errorInfo, true) . "</pre>";
                }
            } else {
                flash("New passwords don't match", "warning");
            }
        }
    }
}
?>

<?php
$email = get_user_email();
$username = get_username();
?>
<div class="container-fluid">
    <form method="POST" onsubmit="return validate(this);">
        <?php render_input(["type" => "email", "id" => "email", "name" => "email", "label" => "Email", "value" => $email, "rules" => ["required" => true]]); ?>
        <?php render_input(["type" => "text", "id" => "username", "name" => "username", "label" => "Username", "value" => $username, "rules" => ["required" => true, "maxlength" => 30]]); ?>
        <!-- DO NOT PRELOAD PASSWORD -->
        <div class="lead">Password Reset</div>
        <?php render_input(["type" => "password", "id" => "cp", "name" => "currentPassword", "label" => "Current Password", "rules" => ["minlength" => 8]]); ?>
        <?php render_input(["type" => "password", "id" => "np", "name" => "newPassword", "label" => "New Password", "rules" => ["minlength" => 8]]); ?>
        <?php render_input(["type" => "password", "id" => "conp", "name" => "confirmPassword", "label" => "Confirm Password", "rules" => ["minlength" => 8]]); ?>
        <?php render_input(["type" => "hidden", "name" => "save"]);/*lazy value to check if form submitted, not ideal*/ ?>
        <?php render_button(["text" => "Update Profile", "type" => "submit"]); ?>
    </form>
</div>

<script>
    function validate(form) {
        let isValid = true; // Initialize isValid as true
        let currentPassword = form.currentPassword.value;
        let newPassword = form.newPassword.value;
        let confirmPassword = form.confirmPassword.value;
        let email = form.email.value;
        let username = form.username.value;

        // TODO: Add other client-side validation...

        // Example of using flash via JavaScript:
        // Find the flash container, create a new element, appendChild
        if (!validateEmail(email)) {
            flash("[CLIENT] Not a valid email.")
            isValid = false;
        }
        if (!validateUsername(username)) {
            flash("[CLIENT] Not a valid username.")
            isValid = false;
        }

        // Password validation logic
        if (currentPassword && newPassword && confirmPassword) {
            
            // Check if the new password is valid
            if (!validatePassword(newPassword)) {
                flash("[CLIENT] Password too short");
                isValid = false;
            }
            // Validate the form
            if (!validatePassword(currentPassword)) {
                flash("[CLIENT] There was a problem.")
                isValid = false;
            }

            if (!validateConfirmPassword(newPassword, confirmPassword)) {
                flash("[CLIENT] Passwords do not match.");
                isValid = false;
            }
        }

    
    return isValid;
    }

</script>
<?php
require_once(__DIR__ . "/../../partials/flash.php");
?>