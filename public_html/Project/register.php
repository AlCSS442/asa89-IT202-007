<?php
require_once(__DIR__ . "/../../lib/functions.php")
?>
<form onsubmit="return validate(this)" method="POST">
    <div>
        <label for="email">Email</label>
        <input id="email" type="email" name="email" required />
    </div>
    <div>
        <label for="pw">Password</label>
        <input type="password" id="pw" name="password" required minlength="8" />
    </div>
    <div>
        <label for="confirm">Confirm</label>
        <input type="password" name="confirm" required minlength="8" />
    </div>
    <input type="submit" value="Register" />
</form>
<script>
    function validate(form) {
        //TODO 1: implement JavaScript validation
        //ensure it returns false for an error and true for success
        
        //Javascript is used for client-side validation, for best security practicies always validate the info on the backend as well(in this case it's PHP)
        //name validation
        let name = form.email.value;
        if (name == ""){
            alert("Please fill out name.");
            return false;
        }
        //password validation
        let password = form.password.value;
        if (password.length < 8){
            alert("Password must be at least 8 characters long.");
            return false;
        }
        //confirming password validation
        let confirm = form.confirm.value;
        if(password !== confirm){
            alert("Passwords do not match.");
            return false;
        }

        return true;
    }
</script>
<?php
 //TODO 2: add PHP Code
 //form will be submitted as a POST request
if (isset($_POST["email"]) && isset($_POST["password"]) && isset($_POST["confirm"])) {

    $email = se($_POST,"email","",false);
    $password = se($_POST,"password","",false) ;
    $confirm = se($_POST,"confirm","",false);
    
    // TODO 3: validate/use
    $hasError = false;

    if (empty($email)) {
        echo "Email must not be empty";
        $hasError = true;
    }
    //sanitize
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        echo "Please enter a valid email <br>";
        $hasError = true;
    }
    
    if (empty($password)) {
        echo "Password must not be empty";
        $hasError = true;
    }
    
    if (empty($confirm)) {
        echo "Confirm password must not be empty";
        $hasError = true;
    }
    
    if (strlen($password) < 8) {
        echo "Password too short";
        $hasError = true;
    }
    
    if ($password !== $confirm) {
        echo "Passwords must match";
        $hasError = true;
    }
    
    if (!$hasError) {
        //echo "Welcome, $email";
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $db = getDB();
        //this statement leaves our database susceptible to SQL injection
        //$stmt = $db->prepare("INSERT INTO Users(email,password) VALUES ($email, $hash)");
        //to fix that, use placeholders and bind the data to the placeholders instead:
        $stmt = $db->prepare("INSERT INTO Users(email,password) VALUES (:email, :password)");
        try{
            $r = $stmt->execute([":email" => $email, ":password" => $hash]);
            echo "Successfully registered!";
        }
        catch(Exception $e){
            echo "There was an error registering <br>";
            echo "<pre>" . var_export($e, true) . "</pre>";
        }
    }
}
    
      
?>