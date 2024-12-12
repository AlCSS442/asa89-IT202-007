<?php 
require_once(__DIR__ . "/../../partials/nav.php");
is_logged_in(true);

// Capture search parameters
$title = se($_GET, "title", "", false);
$severity = se($_GET, "severity", "", false);
$cve_id = se($_GET, "cve_id", "", false);
$published_date = se($_GET, "published_date", "", false);

$column = se($_GET, "column", "", false);
$order = se($_GET, "order", "", false);
$columns = ["title", "severity", "cve_id", "published_date"];
$columnMap = array_map(function ($v) {
    return [$v => $v];
}, $columns);

// Sanitize inputs
if (!in_array($column, $columns)) {
    $column = "title";
}
if (!in_array($order, ["asc", "desc"])) {
    $order = "asc";
}

$params = [];
$params[":user_id"] = get_user_id();

// Build SQL query
$sql = "SELECT NV.id, title, cve_id, description, severity, published_date
        FROM NVD_Vulnerabilities AS NV
        JOIN User_Vulnerabilities AS UV ON UV.vulnerability_id = NV.id
        WHERE UV.user_id = :user_id";

if (!empty($title)) {
    $sql .= " AND title LIKE :title";
    $params[":title"] = "%$title%";
}
if (!empty($severity)) {
    $sql .= " AND severity = :severity";
    $params[":severity"] = $severity;
}
if (!empty($cve_id)) {
    $sql .= " AND cve_id = :cve_id";
    $params[":cve_id"] = $cve_id;
}
if (!empty($published_date)) {
    $sql .= " AND published_date = :published_date";
    $params[":published_date"] = $published_date;
}

$limit = 10;
if (isset($_GET["limit"]) && !is_nan($_GET["limit"])) {
    $limit = (int)$_GET["limit"];
    if ($limit < 0 || $limit > 100) {
        $limit = 10;
    }
}

$sql .= " ORDER BY $column $order LIMIT $limit";

// Execute query
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
    flash("Failed to fetch vulnerabilities", "danger");
}

// Prepare for filters
define("SEVERITY_LEVELS", ["Low", "Medium", "High", "Critical"]);

$total = 0;
$sql_count = "SELECT COUNT(DISTINCT NV.id) AS c
              FROM NVD_Vulnerabilities AS NV
              JOIN User_Vulnerabilities AS UV ON UV.vulnerability_id = NV.id
              WHERE UV.user_id = :user_id";

try {
    $stmt = $db->prepare($sql_count);
    $stmt->execute($params);
    $r = $stmt->fetch();
    if ($r) {
        $total = (int)$r["c"];
    }
} catch (PDOException $e) {
    flash("Error fetching count", "danger");
    error_log(var_export($e, true));
}
?>

<div class="container-fluid">
    <h5>Vulnerability Watchlist</h5>
    <div>
        <form>
            <div class="row">
                <div class="col">
                    <?php render_input(["name" => "title", "label" => "Title", "value" => $title]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "severity", "label" => "Severity", "value" => $severity, "type" => "select", "options" => SEVERITY_LEVELS]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "cve_id", "label" => "CVE ID", "value" => $cve_id]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "published_date", "label" => "Published Date", "value" => $published_date, "type" => "date"]); ?>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <?php render_input(["name" => "column", "label" => "Sort By", "value" => $column, "type" => "select", "options" => $columnMap]); ?>
                </div>
                <div class="col">
                    <?php render_input(["name" => "order", "label" => "Order", "value" => $order, "type" => "select", "options" => [["asc" => "Ascending"], ["desc" => "Descending"]]]); ?>
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
    <div class="row">
        <div class="col">
            Results <?php echo count($results) . "/" . $total; ?>
        </div>
    </div>
    <div class="row">
        <?php foreach ($results as $vuln): ?>
            <div class="col-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title"><?php se($vuln, "title"); ?></h5>
                        <p class="card-text">Severity: <?php se($vuln, "severity"); ?></p>
                        <p class="card-text">CVE ID: <?php se($vuln, "cve_id"); ?></p>
                        <p class="card-text">Published: <?php se($vuln, "published_date"); ?></p>
                        <a href="view_vulnerability.php?id=<?php se($vuln, 'id'); ?>" class="btn btn-primary">View Details</a>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        <?php if (empty($results)): ?>
            <div class="col">No vulnerabilities found</div>
        <?php endif; ?>
    </div>
</div>

<?php
require_once(__DIR__ . "/../../partials/flash.php");
?>
