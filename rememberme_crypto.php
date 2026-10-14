<?php

/**
 * rememberme_crypto
 *
 * The security-critical pieces of the plugin, kept free of Roundcube calls
 * so they can be tested on their own (tests/crypto_test.php):
 *
 *  - a token is a public *selector* (looked up in the database) plus a
 *    secret *validator* that only ever exists in the browser's cookie --
 *    the database stores just a SHA-256 hash of it, compared in constant
 *    time;
 *  - Roundcube needs the IMAP password for every session, so a remembered
 *    login has to keep it. It's encrypted with AES-256-GCM under a key
 *    derived from the validator *and* the server's des_key, so neither a
 *    copy of the database nor the server config alone can recover it --
 *    it needs the cookie from the user's own device as well.
 *
 * @author Gavin Taylor
 *
 * Copyright (C) Gavin Taylor
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
 */
class rememberme_crypto
{
    private const SELECTOR_BYTES = 12;
    private const VALIDATOR_BYTES = 32;
    private const CIPHER = 'aes-256-gcm';
    private const IV_BYTES = 12;
    private const TAG_BYTES = 16;

    /**
     * A fresh token: ['selector' => ..., 'validator' => ...], both
     * URL-safe base64 with no padding.
     */
    public static function new_token(): array
    {
        return [
            'selector' => self::b64(random_bytes(self::SELECTOR_BYTES)),
            'validator' => self::b64(random_bytes(self::VALIDATOR_BYTES)),
        ];
    }

    public static function cookie_value(string $selector, string $validator): string
    {
        return $selector . '.' . $validator;
    }

    /**
     * Splits a cookie value back into [selector, validator], or null if it
     * isn't exactly the shape new_token() produces -- anything else is
     * rejected before it gets near the database.
     */
    public static function parse_cookie(?string $value): ?array
    {
        if (!is_string($value) || !preg_match('/^([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})$/', $value, $m)) {
            return null;
        }

        return ['selector' => $m[1], 'validator' => $m[2]];
    }

    public static function hash_validator(string $validator): string
    {
        return hash('sha256', $validator);
    }

    public static function validator_matches(string $validator, string $stored_hash): bool
    {
        return hash_equals($stored_hash, self::hash_validator($validator));
    }

    /**
     * Encrypts the IMAP password. Returns base64(iv . tag . ciphertext).
     */
    public static function encrypt(string $password, string $validator, string $server_key): string
    {
        $iv = random_bytes(self::IV_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt($password, self::CIPHER, self::key($validator, $server_key),
            \OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_BYTES);

        if ($ciphertext === false) {
            throw new RuntimeException('rememberme: encryption failed');
        }

        return base64_encode($iv . $tag . $ciphertext);
    }

    /**
     * Decrypts a stored password, or returns null if it can't be (wrong
     * cookie, changed server key, tampered data -- GCM authenticates it).
     */
    public static function decrypt(string $blob, string $validator, string $server_key): ?string
    {
        $raw = base64_decode($blob, true);

        if ($raw === false || strlen($raw) <= self::IV_BYTES + self::TAG_BYTES) {
            return null;
        }

        $plain = openssl_decrypt(substr($raw, self::IV_BYTES + self::TAG_BYTES), self::CIPHER,
            self::key($validator, $server_key), \OPENSSL_RAW_DATA,
            substr($raw, 0, self::IV_BYTES), substr($raw, self::IV_BYTES, self::TAG_BYTES));

        return $plain === false ? null : $plain;
    }

    private static function key(string $validator, string $server_key): string
    {
        return hash_hmac('sha256', $validator, 'rememberme:' . $server_key, true);
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
