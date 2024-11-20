<?php
require(__DIR__ . "/../../partials/nav.php");

$result = [];
$cveId = '';
if (isset($_GET["cveId"])) {
    $data = [ //1.  replace data with data you'll be retrieving from my API
        "resultsPerPage" => 5,
        "startIndex" => 0,
        "cveId" => $_GET["cveId"]
    ];
    $cveId = $_GET["cveId"];
    $endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"; //2. REPLACE THE ENDPOINT
    $isRapidAPI = false;


    $result = get($endpoint, "CV_API_KEY", $data, $isRapidAPI);
    //example of cached data to save the quotas, don't forget to comment out the get() if using the cached data for testing
    /* $result = ["status" => 200, "response" => '{
    "Global Quote": {
        "01. symbol": "MSFT",
        "02. open": "420.1100",
        "03. high": "422.3800",
        "04. low": "417.8400",
        "05. price": "421.4400",
        "06. volume": "17861855",
        "07. latest trading day": "2024-04-02",
        "08. previous close": "424.5700",
        "09. change": "-3.1300",
        "10. change percent": "-0.7372%"
    }
}'];*/
    error_log("Response: " . var_export($result, true));
    if (se($result, "status", 400, false) == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        $result = [];
    }
}

$db = getDB();
$query = "INSERT INTO 'Project-cveId'";
foreach($vulnerability as $vuln){
    
}
$db->prepare();

?>
<div class="container-fluid">
    <h1>CVE Info</h1>
    <p>Here is the CVE information for the CVE ID: <?php echo $cveId; ?></p>
    <form>
        <div class="row">
            <label>CVE ID</label>
            <input name="cveId" />
            <input type="submit" value="Fetch CVE Info" />
        </div>
    </form>
    <div class="row">
        <?php if (isset($result['vulnerabilities']) && !empty($result['vulnerabilities'])) : ?>
            <table class="table table-bordered mt-3">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Description</th>
                        <th>Published Date</th>
                        <th>Severity</th>
                        <th>References</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($result['vulnerabilities'] as $vuln) : ?>
                        <tr>
                            <td><?php echo htmlspecialchars($vuln['cve']['id'] ?? 'N/A'); ?></td>
                            <td>
                                <?php
                                // Display the first description in English
                                $descriptions = $vuln['cve']['descriptions'] ?? [];
                                $description = 'No description available';
                                foreach ($descriptions as $desc) {
                                    
                                        $description = $desc['value'];
                                        break;
                                    }
                                
                                echo htmlspecialchars($description);
                                ?>
                            </td>
                            <td><?php echo htmlspecialchars($vuln['cve']['published'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] ?? 'N/A'); ?></td>
                            <td>
                                <?php
                                // Display references as clickable links
                                $references = $vuln['cve']['references'] ?? [];
                                if (!empty($references)) {
                                    foreach ($references as $ref) {
                                        echo '<a href="' . htmlspecialchars($ref['url']) . '" target="_blank">' . htmlspecialchars($ref['url']) . '</a><br>';
                                    }
                                } else {
                                    echo 'No references available';
                                }
                                ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php else : ?>
            <p>No CVE data found or failed to fetch data.</p>
        <?php endif; ?>

    </div>
</div>
<?php
require(__DIR__ . "/../../partials/flash.php");
