<?php
function is_valid_cve_id($cveId)
{
    return preg_match('/CVE-\d{4}-\d{4,7}/', $cveId);
}

?>