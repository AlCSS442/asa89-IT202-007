<?php
// Include the necessary files
require(__DIR__ . "/../../../partials/nav.php");

// Check if the user has admin privileges
if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
}

$id = se($_GET, "id", "", false); // Get the CVE ID from the URL parameter

if (isset($_POST["description"])) {
    // Clean and sanitize POST data
    $quote = [];
    foreach ($_POST as $k => $v) {
        if (!in_array($k, ["description", "severity", "cvss", "vendor", "vulnStatus"])) {
            unset($_POST[$k]);
        }
        $quote[$k] = $v; // Add valid fields to the quote array
    }

    // Prepare the SQL query for updating the CVE record
    $db = getDB();
    $query = "UPDATE `Project-cveId` SET ";
    $params = [];
    foreach ($quote as $k => $v) {
        if ($params) {
            $query .= ",";
        }
        $query .= "$k=:$k";
        $params[":$k"] = $v;
    }

    // Add the CVE ID to the WHERE clause
    $query .= " WHERE id = :id";
    $params[":id"] = $id;

    try {
        // Execute the query
        $stmt = $db->prepare($query);
        $stmt->execute($params);
        flash("CVE updated successfully", "success");
    } catch (PDOException $e) {
        error_log("Something went wrong with the query: " . var_export($e, true));
        flash("An error occurred while updating the CVE.", "danger");
    }
}

$cveData = [];
if (!empty($id)) {
    // Fetch existing CVE data
    $db = getDB();
    $query = "SELECT id, `description`, severity, cvss, vendor, vulnStatus FROM `Project-cveId` WHERE id = :id";
    try {
        $stmt = $db->prepare($query);
        $stmt->execute([":id" => $id]);
        $r = $stmt->fetch();
        if ($r) {
            $cveData = $r;
        }
    } catch (PDOException $e) {
        error_log("Error fetching record: " . var_export($e, true));
        flash("Error fetching CVE data", "danger");
    }
} else {
    flash("Invalid CVE ID passed", "danger");
    die(header("Location: " . get_url("admin/basic_list_page.php")));
}

if ($cveData) {
    $form = [
        ["type" => "text", "name" => "cveId", "placeholder" => "CVE ID", "label" => "CVE ID", "rules" => ["required" => "required"]],
        ["type" => "textarea", "name" => "description", "placeholder" => "Description", "label" => "Description", "rules" => ["required" => "required"]],
        ["type" => "text", "name" => "severity", "placeholder" => "Severity", "label" => "Severity", "rules" => ["required" => "required"]],
        ["type" => "number", "name" => "cvss", "placeholder" => "CVSS Score", "label" => "CVSS Score", "rules" => ["required" => "required"]],
        ["type" => "text", "name" => "vendor", "placeholder" => "Vendor", "label" => "Vendor", "rules" => ["required" => "required"]],
        ["type" => "text", "name" => "vulnStatus", "placeholder" => "Vulnerability Status", "label" => "Vulnerability Status", "rules" => ["required" => "required"]],
    ];

    $keys = array_keys($cveData);
    foreach ($form as $k => $v) {
        if (in_array($v["name"], $keys)) {
            $form[$k]["value"] = $cveData[$v["name"]];
        }
    }
}
?>

<div class="container-fluid">
    <h3>Edit CVE</h3>
    <div>
        <a href="<?php echo get_url("admin/basic_list_page.php"); ?>" class="btn btn-secondary">Back</a>
    </div>
    <form method="POST">
        <?php 
        foreach ($form as $k => $v) {
            render_input($v);
        }
        render_button(["text" => "Update", "type" => "submit"]);
        ?>
    </form>
</div>

<?php
require_once(__DIR__ . "/../../../partials/flash.php");
?>
