<?php
require_once(__DIR__ . "/../../partials/nav.php");

// Check if the user is logged in and has admin privileges
if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
}

$cveId = se($_GET, "cveId", "", false); // Get the CVE ID from the URL parameter

// Check if a CVE ID is provided
if (empty($cveId)) {
    flash("CVE ID is required to edit the record.");
    die("list_cve.php"); // Redirect back to the list page
}

// Fetch the existing data for the given CVE ID
$sql = "SELECT * FROM `Project-cveId` WHERE cveId = :cveId LIMIT 1";
$params = [":cveId" => $cveId];
$db = getDB();
$cveData = null;

try {
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $cveData = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    error_log(var_export($e, true));
    flash("Failed to retrieve data for this CVE.");
    die("list_cve.php");
}

if (!$cveData) {
    flash("CVE ID not found.");
    die("list_cve.php"); // Redirect if CVE ID does not exist
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Handle the form submission
    $description = se($_POST, "description", "", false);
    $severity = se($_POST, "severity", "", false);
    $cvss = se($_POST, "cvss", "", false);
    $vendor = se($_POST, "vendor", "", false);
    $vulnStatus = se($_POST, "vulnStatus", "", false);
    
    // Validation (basic)
    if (empty($description) || empty($severity)) {
        flash("Please fill in all the required fields.");
    } else {
        // Update the record
        $updateSql = "UPDATE `Project-cveId` SET description = :description, severity = :severity, 
                      cvss = :cvss, vendor = :vendor, vulnStatus = :vulnStatus
                      WHERE cveId = :cveId";
        $updateParams = [
            ":description" => $description,
            ":severity" => $severity,
            ":cvss" => $cvss,
            ":vendor" => $vendor,
            ":vulnStatus" => $vulnStatus,
            ":cveId" => $cveId
        ];

        try {
            $stmt = $db->prepare($updateSql);
            $stmt->execute($updateParams);
            flash("CVE updated successfully.");
            die("view_cve.php?cveId=" . $cveId); // Redirect to view page or list page
        } catch (Exception $e) {
            error_log(var_export($e, true));
            flash("Error updating the CVE.");
        }
    }
}

?>

<div class="container-fluid">
    <h1>Edit CVE</h1>
    <form method="POST">
        <div class="row">
            <div class="col">
                <?php render_input(["name" => "cveId", "label" => "CVE ID", "value" => $cveData["cveId"], "readonly" => true]); ?>
            </div>
        </div>
        <div class="row">
            <div class="col">
                <?php render_input(["name" => "description", "label" => "Description", "value" => $cveData["description"], "type" => "textarea"]); ?>
            </div>
        </div>
        <div class="row">
            <div class="col">
                <?php render_input(["name" => "severity", "label" => "Severity", "value" => $cveData["severity"]]); ?>
            </div>
            <div class="col">
                <?php render_input(["name" => "cvss", "label" => "CVSS Score", "value" => $cveData["cvss"]]); ?>
            </div>
        </div>
        <div class="row">
            <div class="col">
                <?php render_input(["name" => "vendor", "label" => "Vendor", "value" => $cveData["vendor"]]); ?>
            </div>
            <div class="col">
                <?php render_input(["name" => "vulnStatus", "label" => "Vulnerability Status", "value" => $cveData["vulnStatus"]]); ?>
            </div>
        </div>
        <div class="row">
            <div class="col">
                <?php render_button(["text" => "Update", "type" => "submit"]); ?>
            </div>
            <div class="col">
                <a href="list_cve.php" class="btn btn-secondary">Cancel</a>
            </div>
        </div>
    </form>
</div>

<?php
require_once(__DIR__ . "/../../partials/flash.php");
?>
