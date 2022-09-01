<?php
/*
This PHP script generates a random password and uses the Go app to password-hash it.
Then it will verify the generated password against the original password in PHP.
*/

// Generate random password
$password = hash('sha256', mt_rand());

// Hash the password using Argon2id via Go application `sample`.
$hash = trim(`sample "$password"`);

echo "Password: $password" . PHP_EOL;
echo "Hashed  : $hash" . PHP_EOL;
echo "Verify ... ";

// Verify the password in PHP
if (password_verify($password, $hash)) {
    echo "OK" . PHP_EOL;
    exit(0);
} else {
    echo "NG" . PHP_EOL;
    exit(1);
}
