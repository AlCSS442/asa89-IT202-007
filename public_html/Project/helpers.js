function flash(message = "", color = "info") {
    let flash = document.getElementById("flash");
    //create a div (or whatever wrapper we want)
    let outerDiv = document.createElement("div");
    outerDiv.className = "row justify-content-center";
    let innerDiv = document.createElement("div");

    //apply the CSS (these are bootstrap classes which we'll learn later)
    innerDiv.className = `alert alert-${color}`;
    //set the content
    innerDiv.innerText = message;

    outerDiv.appendChild(innerDiv);
    //add the element to the DOM (if we don't it merely exists in memory)
    flash.appendChild(outerDiv);
}

function validateEmail(form) {
    let isValid = true;
    const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
    let email = form.email.value;
    if (!emailRegex.test(email)) {
        flash("Please enter a valid email address.");
        isValid = false;
    }
    return isValid;
}

function validateUsername(form) {
    let isValid = true;
    const usernameRegex = /^[A-Za-z0-9_-]{3,30}$/;
    let username = form.username.value;
    if (!usernameRegex.test(username)) {
        flash("Please enter a valid username.");
        isValid = false;
    }
    return isValid;
}



function validatePassword(form) {
    let isValid = true;
    let password = form.password.value;
    if (password.length < 8) {
        flash("Password must be at least 8 characters long.");
        isValid = false;
    }
    return isValid;
}


function validateConfirmPassword(form) {
    let isValid = true;
    let password = form.password.value;
    let confirm = form.confirm.value;
    if (password !== confirm) {
        flash("Passwords do not match.");
        isValid = false;
    }
    return isValid;
}
