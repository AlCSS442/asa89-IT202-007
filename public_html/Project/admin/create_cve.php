<?php
// Note we need to go up 1 more directory
require(__DIR__ . "/../../../partials/nav.php");

if (!has_role("Admin")) {
    flash("You don't have permission to view this page", "warning");
    die(header("Location: $BASE_PATH" . "/home.php"));
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

            <?php render_input(["type" => "text", "name" => "cve_id", "placeholder" => "CVE ID (e.g. CVE-2023-XXXX)", "label" => "CVE ID", "rules" => ["required" => "required"], "attributes" => ["required" => "required", "pattern" => "CVE-\d{4}-\d{4,7}"]]); ?>
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
    const cveId = document.querySelector('[name="cve_id"]').value;
    const pattern = /^CVE-\d{4}-\d{4,7}$/; // Valid CVE format (e.g. CVE-2023-1234)
    
    if (!pattern.test(cveId)) {
        alert("Invalid CVE ID format. Please use CVE-YYYY-XXXX format.");
        return false;
    }
    return true;
}

// JavaScript Validation for Create CVE Form
function validateCreateForm() {
    const cveId = document.querySelector('[name="cve_id"]').value;
    const description = document.querySelector('[name="description"]').value;
    const cvssScore = document.querySelector('[name="cvss_score"]').value;

    // Validate CVE ID format
    const cvePattern = /^CVE-\d{4}-\d{4,7}$/;
    if (!cvePattern.test(cveId)) {
        alert("Invalid CVE ID format. Please use CVE-YYYY-XXXX format.");
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
