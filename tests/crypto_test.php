<?php

// Plain-PHP checks for rememberme_crypto. Run: php tests/crypto_test.php

require __DIR__ . '/../rememberme_crypto.php';

$failures = 0;

function check(string $name, $actual, $expected): void
{
    global $failures;

    if ($actual === $expected) {
        echo "ok   {$name}\n";
    } else {
        $failures++;
        echo "FAIL {$name}\n     expected " . var_export($expected, true) . "\n     got      " . var_export($actual, true) . "\n";
    }
}

$c = 'rememberme_crypto';
$t = $c::new_token();
$cookie = $c::cookie_value($t['selector'], $t['validator']);

check('selector is 16 url-safe chars', (bool) preg_match('/^[A-Za-z0-9_-]{16}$/', $t['selector']), true);
check('validator is 43 url-safe chars', (bool) preg_match('/^[A-Za-z0-9_-]{43}$/', $t['validator']), true);
check('tokens are unique', $c::new_token()['validator'] !== $t['validator'], true);
check('cookie round-trips', $c::parse_cookie($cookie), $t);
check('parse rejects null', $c::parse_cookie(null), null);
check('parse rejects garbage', $c::parse_cookie("x'; DROP TABLE users;--"), null);
check('parse rejects wrong lengths', $c::parse_cookie('abc.def'), null);
check('parse rejects extra parts', $c::parse_cookie($cookie . '.x'), null);

$hash = $c::hash_validator($t['validator']);
check('hash is sha256 hex', strlen($hash), 64);
check('hash is not the validator', $hash !== $t['validator'], true);
check('validator matches its hash', $c::validator_matches($t['validator'], $hash), true);
check('other validator does not match', $c::validator_matches($c::new_token()['validator'], $hash), false);

$key = 'server-des-key-123456789';
$blob = $c::encrypt('s3cret pässwörd', $t['validator'], $key);
check('encrypt/decrypt round-trip (utf-8)', $c::decrypt($blob, $t['validator'], $key), 's3cret pässwörd');
check('ciphertext does not contain the password', str_contains(base64_decode($blob), 's3cret'), false);
check('same password encrypts differently each time', $c::encrypt('s3cret pässwörd', $t['validator'], $key) !== $blob, true);
check('wrong validator cannot decrypt', $c::decrypt($blob, $c::new_token()['validator'], $key), null);
check('wrong server key cannot decrypt', $c::decrypt($blob, $t['validator'], 'another-key'), null);
$raw = base64_decode($blob);
$tampered = base64_encode(substr($raw, 0, -1) . chr(ord(substr($raw, -1)) ^ 1));
check('tampered ciphertext is rejected', $c::decrypt($tampered, $t['validator'], $key), null);
check('junk blob is rejected', $c::decrypt('not base64!!', $t['validator'], $key), null);
check('short blob is rejected', $c::decrypt(base64_encode('short'), $t['validator'], $key), null);

echo $failures ? "\n{$failures} failure(s)\n" : "\nall passed\n";
exit($failures ? 1 : 0);
