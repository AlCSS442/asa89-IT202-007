<?php
//Note: this is to resolve cookie issues with port numbers
$domain = $_SERVER["HTTP_HOST"];
if (strpos($domain, ":")) {
    //strips the port number if present
    $domain = explode(":", $domain)[0];
}
$localWorks = false; //some people have issues with localhost for the cookie params
//if you're one of those people make this false

//this is an extra condition added to "resolve" the localhost issue for the session cookie
if (($localWorks && $domain == "localhost") || $domain != "localhost") {
    session_set_cookie_params([
        "lifetime" => 60 * 60,
        "path" => "/Project", //when you use a session by default, it sets the default path to the root of the web server. But if you're on a shared
                              //server and depending on how the shared server has the environment set up, your cookie may be applicable to other peoples' sites
                              //if you have a special screen that's private to certain users and you're using a session id cookie to authenticate to a server side
                              //session, someone else can elevate their user, which will give them that cookie, give them that server-side session b/c it's a shared server
                              //and they'll be able to navigate your application and access your application by restricting it to ma more refined domain and path
                              // specifiying the path to /Project locks your session to your directory only; only cookies to your application would work
        //"domain" => $_SERVER["HTTP_HOST"] || "localhost",
        "domain" => $domain,
        "secure" => true,
        "httponly" => true, //meaning javascript can't access this cookie, otherwise javascript can manipulate the cookie and hijack the session
        "samesite" => "lax"
    ]);
}
session_start();
//include functions here so we can have it on every page that uses the nav bar
//that way we don't need to include so many other files on each page
//nav will pull in functions and functions will pull in db
require(__DIR__ . "/../lib/functions.php");
?>
<nav>
    <ul>
        <?php if (is_logged_in()) : ?>
            <li><a href="home.php">Home</a></li> <!-- In conditional html, location matters the most. Always want the login first and logout last -->
        <?php endif; ?>
        <?php if (!is_logged_in()) : ?>
            <li><a href="login.php">Login</a></li>
            <li><a href="register.php">Register</a></li>
        <?php endif; ?>
        <?php if (is_logged_in()) : ?>
            <li><a href="logout.php">Logout</a></li>
        <?php endif; ?>
    </ul>
</nav>