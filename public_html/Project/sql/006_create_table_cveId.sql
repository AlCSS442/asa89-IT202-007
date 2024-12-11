CREATE TABLE IF NOT EXISTS `Project-cveId` (
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `cveId` VARCHAR(50) NOT NULL,  -- Increased size for cveId
    `description` TEXT NOT NULL,  -- Lowercase column name
    `published_date` DATE NOT NULL,  -- Fixed column name and size
    `references` VARCHAR(1000) NOT NULL,  -- Increased size for references
    `severity` VARCHAR(50) NOT NULL,


    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `modified` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE(cveId)  
);
