<?php
function fetch_cve_data($cveId)
{
    // Validate CVE ID format
    if (!preg_match('/CVE-\d{4}-\d{4,7}/', $cveId)) {
        return ["error" => "Invalid CVE ID format"];
    }

    // API parameters
    $data = [
        "startIndex" => 0,
        "resultsPerPage" => 10,
        "cveId" => $cveId
    ];
    $endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    $isRapidAPI = false;

    // Fetch CVE data from API
    $result = get($endpoint, "CV_API_KEY", $data, $isRapidAPI);

    // Log the raw API response for debugging
    error_log("Raw API Response: " . var_export($result, true));

    // Check if the response has the expected format and a valid status
    if (isset($result['status']) && $result['status'] == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        return ["error" => "Failed to fetch data or invalid response"];
    }

    // Log the decoded API response for debugging
    error_log("Decoded API Response: " . var_export($result, true));

    // Check if vulnerabilities are present in the response
    $vulnerabilities = $result["vulnerabilities"] ?? [];
    if (empty($vulnerabilities)) {
        return ["error" => "No vulnerabilities found for the given CVE ID"];
    }

    // Extract and parse vulnerabilities
    $parsedData = [];
    foreach ($vulnerabilities as $vuln) {
        $description = '';
        $descriptions = $vuln['cve']['descriptions'] ?? [];
        
        // Look for English descriptions
        foreach ($descriptions as $desc) {
            if ($desc['lang'] === 'en') {
                $description = $desc['value'];
                break;
            }
        }

        // Prepare the parsed data
        $parsedData[] = [
            "cveId" => $vuln['cve']['id'] ?? 'N/A',
            "description" => $description,
            "published_date" => $vuln['cve']['published'] ?? 'N/A',
            "severity" => $vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] ?? 'N/A',
            "references" => array_map(function ($ref) {
                return $ref['url'] ?? 'N/A';
            }, $vuln['cve']['references'] ?? []),
            "lastModified" => $vuln['cve']['lastModified'] ?? 'N/A',
            "vulnStatus" => $vuln['cve']['vulnStatus'] ?? 'N/A',
            "sourceIdentifier" => $vuln['cve']['sourceIdentifier'] ?? 'N/A',
        ];
    }

    // Check if no data was found after processing
    if (empty($parsedData)) {
        return ["error" => "No relevant data found for the given CVE ID"];
    }

    return $parsedData;
}
?>