// Stored user passwords (users[].password, NVS "bleusers").
//
// Format, 53 characters:  $p1$<salt>$<hash>
//   salt = 12 random bytes, base64url without padding (16 characters)
//   hash = PBKDF2-HMAC-SHA256(password, salt, PW_ITERATIONS) cut to 24 bytes,
//          base64url without padding (32 characters)
//
// The web app computes exactly the same thing in the browser (lib/utils/
// bfa_password_hash.dart), so a password set there reaches the PLC only as a
// hash. Passwords stored by older firmware in plain text are converted at boot
// (loadUsers()).
#pragma once

#include <stddef.h>
#include <stdint.h>

static const unsigned PW_ITERATIONS = 2000;
static const size_t   PW_SALT_LEN   = 12;
static const size_t   PW_HASH_LEN   = 24;
static const size_t   PW_STORED_LEN = 53;   // without the NUL

// Hashes `password` with a fresh random salt into `out` (at least 54 bytes).
bool pwHash(const char *password, char *out, size_t cap);

// Same, with a given salt (for the self-test and the web app's test vector).
bool pwHashWithSalt(const char *password, const uint8_t salt[PW_SALT_LEN], char *out, size_t cap);

// True if `password` matches `stored`. A `stored` that is not in the format
// above is compared as plain text (records not converted yet).
bool pwVerify(const char *password, const char *stored);

// True if `stored` is in the format above.
bool pwIsHash(const char *stored);

// Checks the PBKDF2 code against the published test vector (RFC 7914 §11) and
// against the web app's vector. Prints the result; false means passwords set
// in the web app would not work on this PLC.
bool pwSelfTest();
