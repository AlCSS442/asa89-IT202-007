<?php
//create form to insert custom data into your table (can use the helper code or just DIY)

// Note we need to go up 1 more directory
require(__DIR__ . "/../../../partials/nav.php");

if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
}

$name = se($_POST, "cveid", "", false);
// Sanitize and fetch POST data
$cve_id = se($_POST, "cveid", "", false);
$description = se($_POST, "description", "", false);
$cvss_score = se($_POST, "cvss_score", "", false);
$published_date = se($_POST, "published_date", "", false);
$cve_type = se($_POST, "cve_type", "", false);
$references = se($_POST, "references", "", false);

// Check if all fields are set
if (isset($_POST["cve_id"]) && isset($_POST["description"]) && isset($_POST["cvss_score"]) && isset($_POST["published_date"]) && isset($_POST["cve_type"]) && isset($_POST["references"])) {

    // Validate that the CVE ID format is correct 
    if (!preg_match("/^CVE-\d{4}-\d{4,7}$/", $cve_id)) {
        flash("Invalid CVE ID format. Please use CVE-YYYY-XXXX format.");
    } else {
        // Sanitize and clean inputs
        $cve_id = htmlspecialchars($cve_id);
        $description = htmlspecialchars($description);
        $cvss_score = htmlspecialchars($cvss_score);
        $published_date = htmlspecialchars($published_date);
        $cve_type = htmlspecialchars($cve_type);
        $references = htmlspecialchars($references);

        // Check if required fields are not empty
        if (empty($cve_id) || empty($description) || empty($cvss_score) || empty($published_date) || empty($cve_type) || empty($references)) {
            flash("All fields are required.", "warning");
        } else {
            // Insert into the database
            $db = getDB();
            $stmt = $db->prepare("INSERT INTO CVE (cve_id, description, cvss_score, published_date, cve_type, references) 
                                  VALUES(:cve_id, :description, :cvss_score, :published_date, :cve_type, :references)");

            try {
                // Execute the query with the data
                $stmt->execute([
                    ":cve_id" => $cve_id,
                    ":description" => $description,
                    ":cvss_score" => $cvss_score,
                    ":published_date" => $published_date,
                    ":cve_type" => $cve_type,
                    ":references" => $references
                ]);
                flash("Successfully created CVE: $cve_id!", "success");
            } catch (PDOException $e) {
                // Handle potential duplicate CVE ID error
                if ($e->errorInfo[1] === 1062) {
                    flash("A CVE with this ID already exists, please try another", "warning");
                } else {
                    flash("Unknown error occurred, please try again", "danger");
                    error_log(var_export($e->errorInfo, true));
                }
            }
        }
    }
}
?>

<?php
// TODO Handle manual CVE creation
?>
<div class="container-fluid">
    <h3>Create or Fetch CVE</h3>
    <ul class="nav nav-tabs">
        <li class="nav-item">
            <a class="nav-link bg-success" href="#" onclick="switchTab('create')">Create</a>
        </li>
        <li class="nav-item">
            <a class="nav-link bg-success" href="#" onclick="switchTab('fetch')">Fetch</a>
        </li>
    </ul>
    <!-- Fetch CVE Form -->
    <div id="fetch" class="tab-target">
        <form method="POST" onsubmit="return validateFetchForm()">
            <?php render_input(["type" => "search", "name" => "cve_id", "placeholder" => "CVE ID (e.g. CVE-2023-XXXX)", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>
            <?php render_input(["type" => "hidden", "name" => "action", "value" => "fetch"]); ?>
            <?php render_button(["text" => "Search", "type" => "submit",]); ?>
        </form>
    </div>
    <!-- Create CVE Form -->
    <div id="create" style="display: none;" class="tab-target">
        <form method="POST" onsubmit="return validateCreateForm()">

            <?php render_input(["type" => "text", "name" => "cveid", "placeholder" => "CVE ID (e.g. CVE-2023-XXXX)", "label" => "CVE ID", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>
            <?php render_input(["type" => "text", "name" => "description", "placeholder" => "CVE Description", "label" => "CVE Description", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>

            <!-- Bootstrap Dropdown for CVSS Score -->
            <div class="form-group">
                <label for="cvss_score">CVSS Score</label>
                <select name="cvss_score" id="cvss_score" class="form-control" required>
                    <option value="" disabled selected>Select CVSS Score</option>
                    <option value="high">High</option>
                    <option value="low">Low</option>
                </select>
            </div>

            <?php render_input(["type" => "date", "name" => "published_date", "placeholder" => "Published Date", "label" => "Published Date", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>
            <?php render_input(["type" => "text", "name" => "cve_type", "placeholder" => "CVE Type (e.g. Vulnerability, Exploit)", "label" => "CVE Type", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>
            <?php render_input(["type" => "text", "name" => "references", "placeholder" => "References (separate with commas)", "label" => "References", "rules" => ["required" => "required"], "attributes" => ["required" => "required"]]); ?>

            <?php render_input(["type" => "hidden", "name" => "action", "value" => "create"]); ?>
            <?php render_button(["text" => "Create CVE", "type" => "submit", "text" => "Create"]); ?>
        </form>
    </div>
</div>

<script>
    // JavaScript Validation for Fetch CVE Form
    function validateFetchForm() {
        const cveId = document.querySelector('[name="cveid"]').value;
        const pattern = /^CVE-\d{4}-\d{4,7}$/; // Valid CVE format (e.g. CVE-2023-1234)

        if (!pattern.test(cveId)) {
            alert("Invalid CVE ID format. Please use CVE-YYYY-XXXX format.");
            return false;
        }

        return true;
    }

    // JavaScript Validation for Create CVE Form
    function validateCreateForm() {
        const cveId = document.querySelector('[name="cveid"]').value;
        const description = document.querySelector('[name="description"]').value;
        const cvssScore = document.querySelector('[name="cvss_score"]').value;

        // Validate CVE ID format
        const cvePattern = /^CVE-\d{4}-\d{4,7}$/;
        if (!cvePattern.test(cveId)) {
            alert("Invalid CVE ID format. Please use CVE-YYYY-XXXX format." + cveId);
            return false;
        }

        // Validate description (non-empty)
        if (!description.trim()) {
            alert("CVE description is required.");
            return false;
        }

        // Validate CVSS Score HIGH VS LOW
        if (cvssScore !== "high" && cvssScore !== "low") {
            alert("CVSS Score must be either 'High' or 'Low'.");
            return false;
        }

       /* 
        // Validate published date
        if (!publishedDate) {
            alert("Published date is required.");
            return false;
        }

        // Check if the published date is in a valid date format
        const dateObj = new Date(publishedDate);
        if (isNaN(dateObj.getTime())) {
            alert("Invalid date format. Please use YYYY-MM-DD format.");
            return false;
        }

        // Check if the published date is in the future
        const today = new Date();
        if (dateObj > today) {
            alert("Published date cannot be in the future.");
            return false;
        }
            */


        //validate references 
        if (!references.trim()) {
            alert("References are required.");
            return false;
        }

        // Check if references are in a valid comma-separated format (basic validation)
        const referenceList = references.split(",");
        for (let ref of referenceList) {
            if (!isValidURL(ref.trim())) {
                alert("One or more references are in an invalid format.");
                return false;
            }
        }


        return true;
    }

    function switchTab(tab) {
        let target = document.getElementById(tab);
        if (target) {
            let eles = document.getElementsByClassName("tab-target");
            for (let ele of eles) {
                ele.style.display = (ele.id === tab) ? "block" : "none";
            }
        }
    }
</script>

<?php
// Note we need to go up 1 more directory
require_once(__DIR__ . "/../../../partials/flash.php");
?>