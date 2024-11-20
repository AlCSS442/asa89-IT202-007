<?php
require_once(__DIR__ . "/../../partials/nav.php");
?>
<div class="container-fluid">
    <form onsubmit="return validate(this)" method="POST">
        <?php render_input(["type" => "text", "id" => "email", "name" => "email", "label" => "Email/Username", "rules" => ["required" => true]]); ?>
        <?php render_input(["type" => "password", "id" => "password", "name" => "password", "label" => "Password", "rules" => ["required" => true, "minlength" => 8]]); ?>
        <?php render_button(["text" => "Login", "type" => "submit"]); ?>
    </form>
</div>
<script>
    function validate(form) {
        //TODO 1: implement JavaScript validation
        //ensure it returns false for an error and true for success

        //Javascript is used for client-side validation, for best security practicies always validate the info on the backend as well(in this case it's PHP)

        //so I created helper functions and am just going to call them here

        let isValid = true;
        let password = form.password.value;
        let email = form.email.value;


        if (email === "") {
            flash("[Client] Username/email must be filled out.")
            isValid = false;
        }

        if (password === "") {
            flash("[Client] Password must be filled in.")
            isValid = false;
        }

        // Check if the value contains '@', since it would tell me if it's an email or username
        if (email.includes('@')) {
            // If it's an actual email, validate it...
            if (!validateEmail(email)) {
                flash("[CLIENT] Not a valid email.")
                isValid = false;
            }
        } else {
            // If it's not an email, validate the username
            if (!validateUsername(email)) {
                flash("[CLIENT] Invalid username.");
                isValid = false;
            }
        }

        // If either email or username is valid, then validate the password
        if (!validatePassword(password)) {
            flash("[CLIENT] Password is not valid.")
            isValid = false;
        }

        return isValid;
    }
</script>
<?php
//TODO 2: add PHP Code
if (isset($_POST["email"]) && isset($_POST["password"])) {
    $email = se($_POST, "email", "", false);
    $password = se($_POST, "password", "", false);

    //TODO 3
    $hasError = false;
    if (empty($email)) {
        flash("Email must be provided <br>");
        $hasError = true;
    }
    if (str_contains($email, "@")) {
        //sanitize
        $email = sanitize_email($email);
        //validate
        if (!is_valid_email($email)) {
            flash("Invalid email address");
            $hasError = true;
        }
    } else {
        if (!is_valid_username($email)) {
            flash("Invalid username");
            $hasError = true;
        }
    }
    if (empty($password)) {
        flash("Password must be provided <br>");
        $hasError = true;
    }
    if (!is_valid_password($password)) {
        flash("Password must be at least 8 characters long <br>");
        $hasError = true;
    }
    if (!$hasError) {
        //TODO 4
        $db = getDB();
        $stmt = $db->prepare("SELECT id, email, username, password from Users where email = :email or username = :email");
        try {
            $r = $stmt->execute([":email" => $email]);
            if ($r) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($user) {
                    $hash = $user["password"];
                    unset($user["password"]);
                    if (password_verify($password, $hash)) {
                        $_SESSION["user"] = $user;
                        try {
                            //lookup potential roles
                            $stmt = $db->prepare("SELECT Roles.name FROM Roles 
                        JOIN UserRoles on Roles.id = UserRoles.role_id 
                        where UserRoles.user_id = :user_id and Roles.is_active = 1 and UserRoles.is_active = 1");
                            $stmt->execute([":user_id" => $user["id"]]);
                            $roles = $stmt->fetchAll(PDO::FETCH_ASSOC); //fetch all since we'll want multiple
                        } catch (Exception $e) {
                            error_log(var_export($e, true));
                        }
                        //save roles or empty array
                        if (isset($roles)) {
                            $_SESSION["user"]["roles"] = $roles; //at least 1 role
                        } else {
                            $_SESSION["user"]["roles"] = []; //no roles
                        }
                        flash("Welcome, " . get_username());
                        die(header("Location: home.php"));
                    } else {
                        flash("Invalid password");
                    }
                } else {
                    flash("Email not found");
                }
            }
        } catch (Exception $e) {
            flash("<pre>" . var_export($e, true) . "</pre>");
        }
    }
}
?>
<?php require_once(__DIR__ . "/../../partials/flash.php");
