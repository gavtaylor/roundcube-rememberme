-- rememberme: one row per remembered device.
--
-- selector       public half of the cookie, used to find the row
-- validator_hash SHA-256 of the secret half; the secret itself is never
--                stored server-side
-- secret         the IMAP password, AES-256-GCM encrypted under a key
--                derived from the validator and the server's des_key, so
--                this table alone can't be used to recover it
-- username/host  what Roundcube needs to log the session back in

CREATE TABLE IF NOT EXISTS `rememberme_tokens` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `selector` CHAR(16) NOT NULL,
    `validator_hash` CHAR(64) NOT NULL,
    `secret` TEXT NOT NULL,
    `username` VARCHAR(255) NOT NULL,
    `host` VARCHAR(255) NOT NULL,
    `created` DATETIME NOT NULL,
    `last_used` DATETIME NOT NULL,
    `expires` DATETIME NOT NULL,
    `user_agent` VARCHAR(255) NOT NULL DEFAULT '',
    `ip` VARCHAR(45) NOT NULL DEFAULT '',
    PRIMARY KEY (`id`),
    UNIQUE KEY `rememberme_selector` (`selector`),
    KEY `rememberme_user` (`user_id`),
    KEY `rememberme_expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
