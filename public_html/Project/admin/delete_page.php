<?php
require(__DIR__ . "/../../../partials/nav.php");

// Check if the user is logged in and has admin privileges
if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
}
$cveId = se($_GET, "cveId", "", false); // Get the CVE ID from the URL parameter

// Check if a CVE ID is provided
if (empty($cveId)) {
    flash("CVE ID is required to delete the record.");
    die(header("Location: $BASE_PATH" . "/basic_list_page.php")); // Redirect back to the list page
}

// Delete the record from the database
$sql = "DELETE FROM `Project-cveId` WHERE cveId = :cveId LIMIT 1";
$params = [":cveId" => $cveId];
$db = getDB();

try {
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    if ($stmt->rowCount() > 0) {
        flash("CVE record deleted successfully.");
    } else {
        flash("No record found with that CVE ID.");
    }
} catch (Exception $e) {
    error_log(var_export($e, true));
    flash("Error deleting the CVE record.");
}

// Redirect to the list page after deletion
die("list_cve.php");

?>