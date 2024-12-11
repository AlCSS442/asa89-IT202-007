<?php
require(__DIR__ . "/../../partials/nav.php");

$result = [];
$cveId = '';
$db = getDB();

if (isset($_GET["cveId"])) {
    $cveId = $_GET["cveId"]; // Ensure cveId is captured first

    // Validation for cve-id format
    if (!is_valid_cve_id($cveId)) {
        echo "<p>Invalid CVE ID format. Please provide a valid CVE ID.</p>";
        return;
    }

    echo "<p>Valid CVE ID: $cveId</p>";

    //$result = fetch_cve_data($cveId); //added helper function


    // simulated result (can simply comment this out and uncomment the get() above)
    $result = ["status" => 200, "response" => ' {
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
        }'];
    error_log("API Response RAW: " . var_export($result, true));

    $result = json_decode($result["response"], true);

    error_log("API Response Decoded: " . var_export($result, true));

    // Inserting or updating database records for CVE data (only after fetching the result)
    if (isset($result['vulnerabilities'])) {
        $data = [];
        foreach ($result['vulnerabilities'] as $vuln) {
            $details = extract_vulnerability_details($vuln);
            array_push($data, $details);
        }
        try {
            $result = insert('Project-cveId', $data, ['debug' => true, "update_duplicate" => true]);
            error_log("Inserted CVE record: " . json_encode($result));
        } catch (Exception $e) {
            error_log("Failed to insert CVE record: " . $e->getMessage());
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
                        <th>Last Modified</th>
                        <th>Vulnerability Status</th>
                        <th>Source Identifier</th>
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
                            <td><?php echo htmlspecialchars($vuln['cve']['lastModified'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($vuln['cve']['vulnStatus'] ?? 'N/A'); ?></td>
                            <td><?php echo htmlspecialchars($vuln['cve']['sourceIdentifier'] ?? 'N/A'); ?></td>
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