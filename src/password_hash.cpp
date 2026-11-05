#include "password_hash.h"

#include <Arduino.h>
#include <string.h>
#include <esp_system.h>
#include <mbedtls/md.h>

namespace {

const char kB64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// base64url without padding. `out` needs 4 * ceil(n / 3) + 1 bytes.
size_t b64urlEncode(const uint8_t *in, size_t n, char *out) {
  size_t o = 0;
  for (size_t i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < n) v |= in[i + 2];
    out[o++] = kB64url[(v >> 18) & 63];
    out[o++] = kB64url[(v >> 12) & 63];
    if (i + 1 < n) out[o++] = kB64url[(v >> 6) & 63];
    if (i + 2 < n) out[o++] = kB64url[v & 63];
  }
  out[o] = '\0';
  return o;
}

int b64urlValue(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

// Decodes exactly `n` characters (a multiple of 4) into 3 * n / 4 bytes.
bool b64urlDecode4(const char *in, size_t n, uint8_t *out) {
  if (n % 4 != 0) return false;
  for (size_t i = 0, o = 0; i < n; i += 4, o += 3) {
    int a = b64urlValue(in[i]), b = b64urlValue(in[i + 1]), c = b64urlValue(in[i + 2]), d = b64urlValue(in[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) return false;
    uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
    out[o]     = (uint8_t)(v >> 16);
    out[o + 1] = (uint8_t)(v >> 8);
    out[o + 2] = (uint8_t)v;
  }
  return true;
}

// PBKDF2-HMAC-SHA256 for one output block (outLen <= 32), RFC 8018 §5.2.
bool pbkdf2Sha256(const uint8_t *pw, size_t pwLen, const uint8_t *salt, size_t saltLen, unsigned iterations,
                  uint8_t *out, size_t outLen) {
  if (outLen == 0 || outLen > 32 || saltLen > 60 || iterations == 0) return false;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  uint8_t block[64];
  uint8_t u[32], t[32];
  memcpy(block, salt, saltLen);
  block[saltLen] = 0;   // INT(1), big-endian: the first (and only) block
  block[saltLen + 1] = 0;
  block[saltLen + 2] = 0;
  block[saltLen + 3] = 1;

  bool ok = mbedtls_md_setup(&ctx, info, 1) == 0 && mbedtls_md_hmac_starts(&ctx, pw, pwLen) == 0 &&
            mbedtls_md_hmac_update(&ctx, block, saltLen + 4) == 0 && mbedtls_md_hmac_finish(&ctx, u) == 0;
  if (ok) memcpy(t, u, sizeof(t));
  for (unsigned i = 1; ok && i < iterations; i++) {
    ok = mbedtls_md_hmac_reset(&ctx) == 0 && mbedtls_md_hmac_update(&ctx, u, sizeof(u)) == 0 &&
         mbedtls_md_hmac_finish(&ctx, u) == 0;
    for (size_t k = 0; k < sizeof(t); k++) t[k] ^= u[k];
  }
  if (ok) memcpy(out, t, outLen);
  mbedtls_md_free(&ctx);
  memset(u, 0, sizeof(u));
  memset(t, 0, sizeof(t));
  return ok;
}

bool b64urlChar(char c) { return b64urlValue(c) >= 0; }

}  // namespace

bool pwIsHash(const char *s) {
  if (!s || strlen(s) != PW_STORED_LEN || strncmp(s, "$p1$", 4) != 0 || s[20] != '$') return false;
  for (size_t i = 4; i < PW_STORED_LEN; i++) {
    if (i != 20 && !b64urlChar(s[i])) return false;
  }
  return true;
}

bool pwHashWithSalt(const char *password, const uint8_t salt[PW_SALT_LEN], char *out, size_t cap) {
  if (!password || cap < PW_STORED_LEN + 1) return false;
  uint8_t dk[PW_HASH_LEN];
  if (!pbkdf2Sha256(reinterpret_cast<const uint8_t *>(password), strlen(password), salt, PW_SALT_LEN, PW_ITERATIONS,
                    dk, sizeof(dk)))
    return false;
  char saltText[17], hashText[33];
  b64urlEncode(salt, PW_SALT_LEN, saltText);
  b64urlEncode(dk, sizeof(dk), hashText);
  memset(dk, 0, sizeof(dk));
  snprintf(out, cap, "$p1$%s$%s", saltText, hashText);
  return true;
}

bool pwHash(const char *password, char *out, size_t cap) {
  uint8_t salt[PW_SALT_LEN];
  esp_fill_random(salt, sizeof(salt));
  return pwHashWithSalt(password, salt, out, cap);
}

bool pwVerify(const char *password, const char *stored) {
  if (!password || !stored) return false;
  char candidate[PW_STORED_LEN + 1];
  const char *expect = stored;
  if (pwIsHash(stored)) {
    uint8_t salt[PW_SALT_LEN];
    if (!b64urlDecode4(stored + 4, 16, salt) || !pwHashWithSalt(password, salt, candidate, sizeof(candidate)))
      return false;
    password = candidate;   // compare the two hashes below
  }
  // Constant time over the stored value's length.
  size_t n = strlen(expect), m = strlen(password);
  unsigned char diff = (unsigned char)(n != m);
  for (size_t i = 0; i < n; i++) diff |= (unsigned char)(expect[i] ^ (i < m ? password[i] : 0));
  memset(candidate, 0, sizeof(candidate));
  return diff == 0;
}

bool pwSelfTest() {
  // RFC 7914 §11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1, dkLen=64; the
  // first 32 bytes are the first block, which is what this code computes.
  // (Values checked against Python's hashlib.pbkdf2_hmac.)
  static const uint8_t kRfc[32] = {0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91,
                                   0xc2, 0x25, 0x44, 0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde,
                                   0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc};
  uint8_t dk[32];
  bool rfcOk = pbkdf2Sha256(reinterpret_cast<const uint8_t *>("passwd"), 6, reinterpret_cast<const uint8_t *>("salt"),
                            4, 1, dk, sizeof(dk)) &&
               memcmp(dk, kRfc, sizeof(dk)) == 0;

  // The web app's own test vector (test/bfa_password_hash_test.dart): the same
  // password and salt must give the same stored string on both sides.
  static const uint8_t kSalt[PW_SALT_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
  static const char kWeb[] = "$p1$AAECAwQFBgcICQoL$SHrDcL6wXpKEy6lc7QHn7cRI0fnqpg4A";   // also from hashlib
  char got[PW_STORED_LEN + 1];
  bool webOk = pwHashWithSalt("admin123", kSalt, got, sizeof(got)) && strcmp(got, kWeb) == 0;

  unsigned long t0 = millis();
  char tmp[PW_STORED_LEN + 1];
  pwHash("timing", tmp, sizeof(tmp));
  unsigned long ms = millis() - t0;

  Serial.printf("[PASSWORD] Self-test %s (RFC vector %s, web app vector %s); one hash takes %lu ms\n",
                rfcOk && webOk ? "passed" : "FAILED", rfcOk ? "ok" : "WRONG", webOk ? "ok" : "WRONG", ms);
  return rfcOk && webOk;
}
