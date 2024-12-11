<?php 
require_once(__DIR__ . "/../../partials/nav.php");

// Get the CVE ID from the URL parameter (for example, ?id=123)
$id = (int)se($_GET, "id", -1, false);

// Initialize an empty array to hold the data
$cve = [];

if ($id > 0) {
    // SQL query to fetch the CVE details from the database
    $sql = "SELECT * FROM `Project-cveId` WHERE id = :id";
    try {
        $db = getDB();
        $stmt = $db->prepare($sql);
        $stmt->execute([":id" => $id]);
        $r = $stmt->fetch();
        if ($r) {
            $cve = $r; // Assign the fetched record to $cve
        }
    } catch (PDOException $e) {
        error_log("Error fetching CVE: " . var_export($e, true));
        flash("Error fetching CVE", "danger");
    }
} else {
    flash("Invalid CVE ID", "danger");
}

?>

<?php if ($cve): ?>
    <div class="container mt-5">
        <div class="card">
            <div class="card-header">
                <h3><?php echo htmlspecialchars($cve["cveId"]); ?></h3>
            </div>
            <div class="card-body">
                <h5 class="card-title">Description</h5>
                <p class="card-text"><?php echo htmlspecialchars($cve["description"]); ?></p>

                <h5 class="card-title">Severity</h5>
                <p class="card-text"><?php echo htmlspecialchars($cve["severity"]); ?></p>

                <h5 class="card-title">CVSS Score</h5>
                <p class="card-text"><?php echo htmlspecialchars($cve["cvss"]); ?></p>

                <h5 class="card-title">Vendor</h5>
                <p class="card-text"><?php echo htmlspecialchars($cve["vendor"]); ?></p>

                <h5 class="card-title">Published Date</h5>
                <p class="card-text"><?php echo htmlspecialchars($cve["published_date"]); ?></p>
                
                <!-- If you want to show more details, you can add more fields like references, etc. -->
                <a href="index.php" class="btn btn-secondary">Back to List</a>
            </div>
        </div>
    </div>
<?php else: ?>
    <div class="alert alert-danger mt-5" role="alert">
        Sorry, the CVE with the provided ID does not exist.
    </div>
<?php endif; ?>

<?php 
require_once(__DIR__ . "/../../partials/flash.php");
?>
