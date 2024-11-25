<?php
require(__DIR__ . "/../../partials/nav.php");

$result = [];
$cveId = '';
$db = getDB();

if (isset($_GET["cveId"])) {
    $cveId = $_GET["cveId"]; // Ensure cveId is captured first
    $data = [ // Data to be retrieved from the API
        "resultsPerPage" => 5,
        "startIndex" => 0,
        "resultsPerPage" => 10,
        "cveId" => $cveId
    ];
    
    //using cached data by turning it into a string instead of making a real API request for testing
    $cachedData = '{
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2024-11-25T20:34:16.170",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-30900",
                    "sourceIdentifier": "product-security@apple.com",
                    "published": "2021-08-24T19:15:18.083",
                    "lastModified": "2024-11-21T06:04:55.677",
                    "vulnStatus": "Modified",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apple macOS vulnerability in WebKit"
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.8,
                                    "baseSeverity": "High"
                                }
                            }
                        ]
                    },
                    "references": [
                        {
                            "url": "https://support.apple.com/en-us/HT213717"
                        }
                    ]
                }
            }
        ]
    }';
    // Decode the cached JSON string into a PHP associative array
    $result = json_decode($cachedData, true);

    $endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"; // Endpoint for fetching CVE data
    $isRapidAPI = false;

    // Fetching CVE data from API
    //$result = get($endpoint, "CV_API_KEY", $data, $isRapidAPI);
    error_log("API Response: " . var_export($result, true));

    if (se($result, "status", 400, false) == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        // Log if the API response isn't as expected
        error_log("API call failed or response not as expected.");
        $result = [];
    }
    error_log("API Response: " . var_export($result, true));
    // Inserting or updating database records for CVE data (only after fetching the result)
    if (isset($result['vulnerabilities'])) {
        foreach ($result['vulnerabilities'] as $vuln) {
            // Extract data from API response
            $description = ''; 
            $descriptions = $vuln['cve']['descriptions'] ?? [];
            foreach ($descriptions as $desc) {
                $description = $desc['value'];
                break; // Use the first description
            }

            $published_date = $vuln['cve']['published'] ?? null;
            $severity = $vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] ?? 'N/A';
            $references = '';
            $refs = $vuln['cve']['references'] ?? [];
            foreach ($refs as $ref) {
                $references .= $ref['url'] . '; ';  // Concatenate URLs with a semicolon separator
            }

            // Prepare the SELECT query to check if the CVE already exists
            $query = "SELECT * FROM `Project-cveId` WHERE cve_id = :cve_id";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':cve_id', $vuln['cve']['id']);
            $stmt->execute();

            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            // If the CVE exists, update it, else insert it
            if ($existing) {
                // Update the record if it exists
                $updateQuery = "UPDATE `Project-cveId` SET 
                                description = :description, 
                                published_date = :published_date, 
                                severity = :severity, 
                                references = :references, 
                                modified = NOW() 
                                WHERE cve_id = :cve_id";
                $updateStmt = $db->prepare($updateQuery);
                $updateStmt->bindParam(':cve_id', $vuln['cve']['id']);
                $updateStmt->bindParam(':description', $description);
                $updateStmt->bindParam(':published_date', $published_date);
                $updateStmt->bindParam(':severity', $severity);
                $updateStmt->bindParam(':references', $references);
                $updateStmt->execute();
            } else {
                // Insert new record if it doesn't exist
                $insertQuery = "INSERT INTO `Project-cveId` (cve_id, description, published_date, severity, references, created, modified)
                                VALUES (:cve_id, :description, :published_date, :severity, :references, NOW(), NOW())";
                $insertStmt = $db->prepare($insertQuery);
                $insertStmt->bindParam(':cve_id', $vuln['cve']['id']);
                $insertStmt->bindParam(':description', $description);
                $insertStmt->bindParam(':published_date', $published_date);
                $insertStmt->bindParam(':severity', $severity);
                $insertStmt->bindParam(':references', $references);
                $insertStmt->execute();
            }
        }
    } else {
        error_log("No valid CVE data found in the API response.");
    }
}
?>

<div class="container-fluid">
    <h1>CVE Info</h1>
    <p>Here is the CVE information for the CVE ID: <?php echo htmlspecialchars($cveId); ?></p>
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
                                $descriptions = $vuln['cve']['descriptions'] ?? [];
                                $description = 'No description available';
                                foreach ($descriptions as $desc) {
                                    if ($desc['lang'] === 'en') { // Prioritize English description
                                        $description = $desc['value'];
                                        break;
                                    }
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
?>
