<?php
//basic list page of data from the DB

require_once(__DIR__ . "/../../partials/nav.php");

// Search parameters for filtering the list
$cveId = se($_GET, "cveId", "", false);
$description = se($_GET, "description", "", false);
$severity = se($_GET, "severity", "", false);
$vendor = se($_GET, "vendor", "", false);
$cvss = se($_GET, "cvss", "", false);
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
$columns = ["cveId", "published_date", "severity", "cvss", "vendor"];
$columnMap = array_map(function ($v) {
    return [$v => $v];
}, $columns);

// Sanitize the column and order inputs
if (!in_array($order, ["asc", "desc"])) {
    $order = "desc";
}

$sql = "SELECT * FROM `Project-cveId` WHERE 1=1"; // Used to easily append other conditions
$params = [];
if (!empty($cveId)) {
    $sql .= " AND cveId LIKE :cveId";
    $params[":cveId"] = "%$cveId%";
}
if (!empty($description)) {
    $sql .= " AND description LIKE :description";
    $params[":description"] = "%$description%";
}
if (!empty($severity)) {
    $sql .= " AND severity = :severity";
    $params[":severity"] = $severity;
}
if (!empty($cvss)) {
    $sql .= " AND cvss = :cvss";
    $params[":cvss"] = $cvss;
}
if (!empty($vendor)) {
    $sql .= " AND vendor LIKE :vendor";
    $params[":vendor"] = "%$vendor%";
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
require_once(__DIR__ . "/../../partials/flash.php");
?>
