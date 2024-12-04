<?php
function update_cve_record($db, $data)
{
    $updateQuery = "UPDATE `Project-cveId` SET 
                    `description` = :description, 
                    `published_date` = :published_date, 
                    `severity` = :severity, 
                    `references` = :references,
                    `lastModified` = :lastModified,
                    `vulnStatus` = :vulnStatus,
                    `sourceIdentifier` = :sourceIdentifier
                    WHERE cveId = :cveId";
    $stmt = $db->prepare($updateQuery);
    $stmt->execute($data);
}
?>