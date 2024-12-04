<?php
function cve_exists($db, $cveId)
{
    $query = "SELECT * FROM `Project-cveId` WHERE cveId = :cveId";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':cveId', $cveId);
    $stmt->execute();
    $existing = $stmt->fetch(PDO::FETCH_ASSOC);
    return $existing !== false; // Return true if a record is found, false otherwise
}
?>