<?php
//basic list page of data from the DB

require(__DIR__ . "/../../../partials/nav.php");

if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
}

// Search parameters for filtering the list
$cveId = se($_GET, "cveId", "", false);
$description = se($_GET, "description", "", false);
$severity = se($_GET, "severity", "", false);
$references = se($_GET, "references", "", false);
$vulnStatus = se($_GET, "vulnStatus", "", false);
$sourceIdentifier = se($_GET, "sourceIdentifier", "", false);
$published_date = se($_GET, "published_date", "", false);
$order = se($_GET, "order", "desc", false);

// Pagination limit
$limit = 10;
if (isset($_GET["limit"]) && !is_nan($_GET["limit"])) {
    $limit = (int)$_GET["limit"];
    if ($limit < 0 || $limit > 100) {
        $limit = 10;
    }
}

// Column map for sorting
$columns = ["cveId", "description", "severity", "references", "vulnStatus", "sourceIdentifier", "published_date"];
$columnMap = array_map(function ($v) {
    return [$v => $v];
}, $columns);

// Sanitize the column and order inputs
if (!in_array($order, ["asc", "desc"])) {
    $order = "desc";
}

$sql = "SELECT * FROM `Project-cveId` WHERE id=:id";
$params = [];
if (!empty($id)) {
    $sql .= " AND id LIKE :id";  // Add a condition to filter the 'id'
    $params[":id"] = "%$id%";  // Add the parameter for binding
}

try {
    // Prepare the statement
    $stmt = $db->prepare($sql);

    // Execute the query with the parameters
    $stmt->execute([":id" => $id]); // Binding the 'id' parameter directly in execute
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);  // Fetch the results

    // Process the results...
} catch (PDOException $e) {
    error_log("Error executing query: " . $e->getMessage());
    flash("An error occurred while fetching data", "danger");
}


// Sorting logic
$sql .= " ORDER BY $order";

// Pagination (limit)
$sql .= " LIMIT $limit";

// Database query execution
$db = getDB();
$results = [];
try {
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $r = $stmt->fetchAll();
    if ($r) {
        $results = $r;
    }
} catch (Exception $e) {
    error_log(var_export($e, true));
    error_log("Error occurred while fetching data.");
    flash("Failed to fetch CVE data.");
}

$table = [
    "data" => $results,
    "title" => "CVE List",
    "ignored_columns" => ["id"], // If you have any columns to ignore in the table
    "delete_url" => get_url("delete_cve.php"),
    "view_url" => get_url("view_cve.php")
];

?>

<div class="container-fluid">
    <div>
        <form>
            <div class="row">
                <div class="col">
                    <?php render_input(["name" => "cveId", "label" => "CVE ID", "value" => $cveId]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "description", "label" => "Description", "value" => $description]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "severity", "label" => "Severity", "value" => $severity]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "cvss", "label" => "CVSS Score", "value" => $cvss]); ?>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <?php render_input(["name" => "vendor", "label" => "Vendor", "value" => $vendor]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "order", "label" => "Sort Order", "value" => $order, "type" => "select", "options" => [["asc" => "Ascending"], ["desc" => "Descending"]]]); ?>
                </div>
                <div class="col">
                    <?php render_button(["text" => "Search", "type" => "submit"]); ?>
                </div>
                <div class="col">
                    <a href="?" class="btn btn-secondary">Reset</a>
                </div>
            </div>
        </form>
    </div>

    <?php if (isset($_GET["grid"])): ?>
        <div class="row">
            <?php foreach ($results as $cve): ?>
                <div class="col-3">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo $cve["cveId"]; ?></h5>
                            <p class="card-text"><?php echo $cve["description"]; ?></p>
                            <a href="<?php echo get_url("view_cve.php?id=" . $cve["id"]); ?>" class="btn btn-primary">View</a>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <?php render_table($table); ?>
    <?php endif; ?>
</div>

<?php
require_once(__DIR__ . "/../../../partials/flash.php");
?>