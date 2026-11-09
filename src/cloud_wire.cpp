#include "cloud_wire.h"

#include <stdio.h>
#include <string.h>
#include <ArduinoJson.h>

namespace {

// Length of the valid UTF-8 sequence at `s`, or 0 if the byte there does not
// start one (a stray continuation byte, an overlong form, a surrogate, past
// U+10FFFF, or a sequence cut short).
size_t utf8SeqLen(const unsigned char *s) {
  unsigned char c = s[0];
  if (c < 0x80) return 1;
  size_t n;
  unsigned long cp;
  if (c >= 0xC2 && c <= 0xDF) {
    n = 2;
    cp = c & 0x1F;
  } else if (c >= 0xE0 && c <= 0xEF) {
    n = 3;
    cp = c & 0x0F;
  } else if (c >= 0xF0 && c <= 0xF4) {
    n = 4;
    cp = c & 0x07;
  } else {
    return 0;
  }
  for (size_t i = 1; i < n; i++) {
    if ((s[i] & 0xC0) != 0x80) return 0;
    cp = (cp << 6) | (s[i] & 0x3F);
  }
  if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))) return 0;
  if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
  return n;
}

// Copies `src` into `dst` (cap bytes), never cutting a UTF-8 sequence in two.
void copyUtf8(char *dst, size_t cap, const char *src) {
  if (cap == 0) return;
  size_t len = 0;
  const unsigned char *s = reinterpret_cast<const unsigned char *>(src);
  while (*s) {
    size_t n = utf8SeqLen(s);
    if (n == 0) n = 1;   // invalid byte: copied as is, JSON output replaces it
    if (len + n >= cap) break;
    memcpy(dst + len, s, n);
    len += n;
    s += n;
  }
  dst[len] = '\0';
}

bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

// `src` without leading/trailing ASCII whitespace, into `dst` (UTF-8 safe).
void copyTrimmed(char *dst, size_t cap, const char *src) {
  while (isSpace(*src)) src++;
  size_t n = strlen(src);
  while (n > 0 && isSpace(src[n - 1])) n--;
  char tmp[PHONE_KEY_MAX + 1];
  if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
  memcpy(tmp, src, n);
  tmp[n] = '\0';
  copyUtf8(dst, cap, tmp);
}

// Appends to a fixed buffer; once anything fails to fit, stays failed.
struct Out {
  char  *buf;
  size_t cap;
  size_t len;
  bool   ok;

  void raw(const char *s) {
    size_t n = strlen(s);
    if (!ok || len + n >= cap) {
      ok = false;
      return;
    }
    memcpy(buf + len, s, n + 1);
    len += n;
  }

  // A JSON string body. Bytes above 0x7F become '?': a stored name in another
  // encoding must not make Firestore reject every heartbeat as invalid JSON.
  void str(const char *s) {
    for (; *s; s++) {
      unsigned char c = (unsigned char)*s;
      char tmp[8];
      if (c == '"' || c == '\\') {
        tmp[0] = '\\';
        tmp[1] = (char)c;
        tmp[2] = '\0';
      } else if (c < 0x20) {
        snprintf(tmp, sizeof(tmp), "\\u%04x", c);
      } else {
        tmp[0] = c > 0x7F ? '?' : (char)c;
        tmp[1] = '\0';
      }
      raw(tmp);
    }
  }

  // A JSON string body that keeps valid UTF-8 (names, phone ids and RTDB keys
  // must arrive exactly as they are). Invalid bytes become '?'.
  void utf8(const char *s) {
    const unsigned char *p = reinterpret_cast<const unsigned char *>(s);
    while (*p) {
      size_t n = utf8SeqLen(p);
      if (n > 1) {
        char tmp[5];
        memcpy(tmp, p, n);
        tmp[n] = '\0';
        raw(tmp);
        p += n;
        continue;
      }
      char one[2] = {n == 0 ? '?' : (char)*p, '\0'};
      str(one);   // ASCII: escaped as usual
      p++;
    }
  }

  // "key/sub": a multi-path PATCH field name below an RTDB child key.
  void pathField(const char *key, const char *sub) {
    raw("\"");
    utf8(key);
    if (sub) {
      raw("/");
      raw(sub);
    }
    raw("\":");
  }

  void utf8Value(const char *v) {
    raw("\"");
    utf8(v);
    raw("\"");
  }

  void field(const char *name) {
    raw("\"");
    raw(name);
    raw("\":");
  }

  void stringValue(const char *name, const char *v) {
    field(name);
    raw("{\"stringValue\":\"");
    str(v);
    raw("\"}");
  }

  void boolValue(const char *name, bool v) {
    field(name);
    raw(v ? "{\"booleanValue\":true}" : "{\"booleanValue\":false}");
  }

  // Plain JSON values, as the Realtime Database takes them.
  void plainString(const char *name, const char *v) {
    field(name);
    raw("\"");
    str(v);
    raw("\"");
  }

  void plainBool(const char *name, bool v) {
    field(name);
    raw(v ? "true" : "false");
  }

  void plainUint(const char *name, unsigned long v) {
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%lu", v);
    field(name);
    raw(tmp);
  }
};

}  // namespace

size_t cloudBuildSignIn(char *out, size_t cap, const char *login, const char *key) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{\"email\":\"");
  o.str(login);
  o.raw("\",\"password\":\"");
  o.str(key);
  o.raw("\",\"returnSecureToken\":true}");
  return o.ok ? o.len : 0;
}

size_t cloudBuildHeartbeat(char *out, size_t cap, const char *projectId, const char *plcId,
                           const char *fw, const CloudStatus &s) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{\"writes\":[{\"update\":{\"name\":\"projects/");
  o.str(projectId);
  o.raw("/databases/(default)/documents/plcs/");
  o.str(plcId);
  o.raw("\",\"fields\":{\"status\":{\"mapValue\":{\"fields\":{");

  o.stringValue("fw", fw);
  o.raw(",");
  o.stringValue("ip", s.ip);
  o.raw(",");
  o.stringValue("mac", s.mac);
  o.raw(",");
  o.stringValue("bleMac", s.bleMac);
  o.raw(",");
  char uptime[12];
  snprintf(uptime, sizeof(uptime), "%lu", (unsigned long)s.uptimeS);
  o.field("uptimeS");
  o.raw("{\"integerValue\":\"");
  o.raw(uptime);
  o.raw("\"},");
  if (s.rtc[0]) {
    o.stringValue("rtc", s.rtc);
  } else {
    o.field("rtc");
    o.raw("{\"nullValue\":null}");
  }
  o.raw(",");
  o.boolValue("rtcOk", s.rtcOk);
  o.raw(",");
  o.boolValue("sdOk", s.sdOk);
  o.raw(",");

  o.field("motion");
  o.raw("{\"mapValue\":{\"fields\":{");
  o.boolValue("estop", s.estop);
  o.raw(",");
  o.boolValue("up", s.up);
  o.raw(",");
  o.boolValue("down", s.down);
  o.raw(",");
  o.boolValue("left", s.left);
  o.raw(",");
  o.boolValue("right", s.right);
  o.raw("}}},");

  o.field("ble");
  o.raw("{\"mapValue\":{\"fields\":{");
  o.boolValue("adv", s.bleAdv);
  o.raw(",");
  o.boolValue("conn", s.bleConn);
  o.raw(",");
  o.boolValue("auth", s.bleAuth);
  o.raw(",");
  o.stringValue("user", s.bleUser);
  o.raw("}}}");

  // lastSeen is the server's clock, never the PLC's: firestore.rules requires it.
  o.raw("}}}}},\"updateMask\":{\"fieldPaths\":[\"status\"]},"
        "\"updateTransforms\":[{\"fieldPath\":\"lastSeen\",\"setToServerValue\":\"REQUEST_TIME\"}],"
        "\"currentDocument\":{\"exists\":true}}]}");
  return o.ok ? o.len : 0;
}

int cloudHttpStatus(const char *resp) {
  if (strncmp(resp, "HTTP/1.", 7) != 0 || resp[7] == '\0' || resp[8] != ' ') return 0;
  int code = 0;
  for (int i = 9; i < 12; i++) {
    if (resp[i] < '0' || resp[i] > '9') return 0;
    code = code * 10 + (resp[i] - '0');
  }
  return code;
}

bool cloudJsonString(const char *resp, const char *key, char *out, size_t cap) {
  const char *p = strstr(resp, "\r\n\r\n");
  if (!p) return false;

  char quoted[24];
  int n = snprintf(quoted, sizeof(quoted), "\"%s\"", key);
  if (n <= 0 || (size_t)n >= sizeof(quoted)) return false;

  for (p = strstr(p, quoted); p; p = strstr(p + 1, quoted)) {
    const char *v = p + n;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    if (*v != ':') continue;   // the key's text appeared as a value
    v++;
    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') v++;
    if (*v != '"') continue;
    v++;

    size_t len = 0;
    for (; *v && *v != '"'; v++) {
      if (*v == '\\' && v[1]) v++;   // keep the escaped character, drop the backslash
      if (len + 1 >= cap) return false;
      out[len++] = *v;
    }
    if (*v != '"') return false;   // reply was cut off inside the value
    out[len] = '\0';
    return true;
  }
  return false;
}

bool cloudValidPlcId(const char *s) {
  size_t n = strlen(s);
  if (n < 3 || n > 32 || s[0] == '-') return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

bool cloudValidApiKey(const char *s) {
  size_t n = strlen(s);
  if (n < 1 || n > 64) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  return true;
}

// ---------------- Realtime Database push ----------------

static bool isKeyChar(char c, bool allowDot) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
         (allowDot && c == '.');
}

bool cloudValidDeviceId(const char *s) {
  size_t n = strlen(s);
  if (n < 1 || n > 32) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isKeyChar(s[i], false)) return false;
  }
  return true;
}

bool cloudValidDbSecret(const char *s) {
  size_t n = strlen(s);
  if (n < 1 || n > 64) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isKeyChar(s[i], true)) return false;
  }
  return true;
}

static bool endsWith(const char *s, size_t n, const char *suffix) {
  size_t m = strlen(suffix);
  return n > m && memcmp(s + n - m, suffix, m) == 0;
}

bool cloudParseDbHost(const char *url, char *host, size_t cap) {
  if (cap == 0) return false;
  host[0] = '\0';

  const char *p = url;
  if (strncmp(p, "https://", 8) == 0) {
    p += 8;
  } else if (strstr(p, "://")) {
    return false;   // http:// would send the secret in clear text
  }

  size_t n = 0;
  while (p[n] && p[n] != '/') n++;
  if (p[n] == '/' && p[n + 1] != '\0') return false;   // a path: this is not the database root

  // Lower-case letters, digits, '.' and '-' only: no port, no userinfo, no
  // look-alike host such as "x.firebaseio.com@evil.example".
  if (n < 5 || n >= cap) return false;
  for (size_t i = 0; i < n; i++) {
    char c = p[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
    host[i] = c;
  }
  host[n] = '\0';

  if (host[0] == '.' || host[0] == '-' || strstr(host, "..")) {
    host[0] = '\0';
    return false;
  }
  if (!endsWith(host, n, ".firebaseio.com") && !endsWith(host, n, ".firebasedatabase.app")) {
    host[0] = '\0';
    return false;
  }
  return true;
}

size_t cloudBuildDevicePath(char *out, size_t cap, const char *deviceId, const char *secret) {
  return cloudBuildDbPath(out, cap, deviceId, "", "", secret);
}

size_t cloudBuildDbPath(char *out, size_t cap, const char *deviceId, const char *child, const char *query,
                        const char *secret) {
  if (cap == 0) return 0;
  out[0] = '\0';
  if (!cloudValidDeviceId(deviceId) || !cloudValidDbSecret(secret)) return 0;
  bool hasChild = child && child[0];
  bool hasQuery = query && query[0];
  int n = snprintf(out, cap, "/devices/%s%s%s.json?%s%sauth=%s", deviceId, hasChild ? "/" : "", hasChild ? child : "",
                   hasQuery ? query : "", hasQuery ? "&" : "", secret);
  if (n > 0 && (size_t)n < cap) return (size_t)n;
  memset(out, 0, cap);   // a cut-off path still held part of the secret
  return 0;
}

size_t cloudUrlEncode(const char *in, char *out, size_t cap) {
  static const char kHexDigits[] = "0123456789ABCDEF";
  if (cap == 0) return 0;
  size_t len = 0;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(in); *p; p++) {
    unsigned char c = *p;
    bool plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                 c == '.' || c == '~';
    size_t need = plain ? 1 : 3;
    if (len + need >= cap) {
      out[0] = '\0';
      return 0;
    }
    if (plain) {
      out[len++] = (char)c;
    } else {
      out[len++] = '%';
      out[len++] = kHexDigits[c >> 4];
      out[len++] = kHexDigits[c & 0x0F];
    }
  }
  out[len] = '\0';
  return len;
}

const char *cloudHttpBody(const char *resp) {
  const char *p = strstr(resp, "\r\n\r\n");
  return p ? p + 4 : nullptr;
}

size_t cloudBuildDeviceUpdate(char *out, size_t cap, const char *fw, unsigned heartbeatIntervalS,
                              const CloudStatus &s) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  if (s.rtc[0]) {
    o.plainString("heartbeat", s.rtc);
    o.raw(",");
  }
  o.plainUint("heartbeatIntervalSec", heartbeatIntervalS);
  o.raw(",");
  o.plainString("fw", fw);
  o.raw(",");
  o.plainString("localIp", s.ip);
  o.raw(",");
  o.plainString("mac", s.mac);
  o.raw(",");
  o.plainString("bleMac", s.bleMac);
  o.raw(",");

  o.field("status");
  o.raw("{");
  o.plainUint("uptimeS", s.uptimeS);
  o.raw(",");
  o.plainUint("freeHeap", s.freeHeap);
  o.raw(",");
  o.plainUint("minFreeHeap", s.minFreeHeap);
  o.raw(",");
  o.plainBool("rtcOk", s.rtcOk);
  o.raw(",");
  o.plainBool("sdOk", s.sdOk);
  o.raw(",");
  o.plainBool("estop", s.estop);
  o.raw(",");
  o.plainBool("up", s.up);
  o.raw(",");
  o.plainBool("down", s.down);
  o.raw(",");
  o.plainBool("left", s.left);
  o.raw(",");
  o.plainBool("right", s.right);
  o.raw(",");
  o.plainBool("bleAdv", s.bleAdv);
  o.raw(",");
  o.plainBool("bleConn", s.bleConn);
  o.raw(",");
  o.plainBool("bleAuth", s.bleAuth);
  o.raw(",");
  o.plainString("bleUser", s.bleUser);
  o.raw("},");

  // What the web app's Network Settings form shows (never the Wi-Fi password).
  o.field("network");
  o.raw("{");
  o.plainString("bleName", s.bleName);
  o.raw(",");
  o.plainString("ssid", s.wifiSsid);
  o.raw(",");
  o.plainBool("restartPending", s.netRestartPending);
  o.raw("},");

  // How the event upload is doing (the web app's Events & Logs shows it).
  o.field("eventUpload");
  o.raw("{");
  o.plainString("state", s.evState);
  o.raw(",");
  o.plainUint("queued", s.evQueued);
  o.raw(",");
  o.plainUint("uploaded", s.evUploaded);
  o.raw(",");
  o.plainUint("noClock", s.evNoClock);
  o.raw(",");
  o.plainUint("dropped", s.evDropped);
  o.raw("}}");
  return o.ok ? o.len : 0;
}

// ---------------- sync with the web app ----------------

bool cloudPhoneKey(const char *phoneId, char *out, size_t cap) {
  if (cap == 0) return false;
  out[0] = '\0';
  while (isSpace(*phoneId)) phoneId++;
  size_t n = strlen(phoneId);
  while (n > 0 && isSpace(phoneId[n - 1])) n--;
  if (n == 0 || n >= cap) return false;

  const unsigned char *s = reinterpret_cast<const unsigned char *>(phoneId);
  size_t i = 0;
  while (i < n) {
    size_t seq = utf8SeqLen(s + i);
    if (seq > 1 && i + seq <= n) {
      memcpy(out + i, s + i, seq);
      i += seq;
      continue;
    }
    unsigned char c = s[i];
    bool bad = seq == 0 || seq > 1 || c < 0x20 || c == 0x7F || c == '.' || c == '$' || c == '#' || c == '[' ||
               c == ']' || c == '/';
    out[i++] = bad ? '_' : (char)c;
  }
  out[n] = '\0';
  return true;
}

bool cloudUserKey(const char *email, char *out, size_t cap) {
  static const char kHex[] = "0123456789ABCDEF";
  if (cap == 0) return false;
  out[0] = '\0';
  while (isSpace(*email)) email++;
  size_t n = strlen(email);
  while (n > 0 && isSpace(email[n - 1])) n--;
  if (n == 0) return false;

  const unsigned char *s = reinterpret_cast<const unsigned char *>(email);
  size_t len = 0;
  size_t i = 0;
  while (i < n) {
    size_t seq = utf8SeqLen(s + i);
    if (seq > 1 && i + seq <= n) {   // valid non-ASCII: kept as is (only ASCII is lower-cased)
      if (len + seq >= cap) return false;
      memcpy(out + len, s + i, seq);
      len += seq;
      i += seq;
      continue;
    }
    unsigned char c = s[i++];
    if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
    bool esc = seq != 1 || c < 0x20 || c == 0x7F || c == '%' || c == '.' || c == '$' || c == '#' || c == '[' ||
               c == ']' || c == '/';
    if (esc) {
      if (len + 3 >= cap) return false;
      out[len++] = '%';
      out[len++] = kHex[c >> 4];
      out[len++] = kHex[c & 0x0F];
    } else {
      if (len + 1 >= cap) return false;
      out[len++] = (char)c;
    }
  }
  out[len] = '\0';
  return true;
}

// The value of a key the Realtime Database treats as a 32-bit integer: the
// client SDKs' rule, /^-?(0*)\d{1,10}$/ and inside the int32 range.
static bool rtdbIntKey(const char *s, long long &v) {
  const char *p = s;
  bool neg = *p == '-';
  if (neg) p++;
  if (!*p) return false;
  while (*p == '0' && p[1] >= '0' && p[1] <= '9') p++;   // leading zeros, keeping one digit
  size_t digits = 0;
  long long val = 0;
  for (; *p; p++) {
    if (*p < '0' || *p > '9') return false;
    if (++digits > 10) return false;
    val = val * 10 + (*p - '0');
  }
  if (digits == 0) return false;
  if (neg) val = -val;
  if (val < -2147483648LL || val > 2147483647LL) return false;
  v = val;
  return true;
}

int cloudRtdbKeyCompare(const char *a, const char *b) {
  long long ia = 0, ib = 0;
  bool aInt = rtdbIntKey(a, ia);
  bool bInt = rtdbIntKey(b, ib);
  if (aInt && bInt) {
    if (ia != ib) return ia < ib ? -1 : 1;
    size_t la = strlen(a), lb = strlen(b);   // "007" after "7", as the SDKs order them
    return la == lb ? 0 : (la < lb ? -1 : 1);
  }
  if (aInt != bInt) return aInt ? -1 : 1;
  int c = strcmp(a, b);
  return c == 0 ? 0 : (c < 0 ? -1 : 1);
}

static void rejectOp(QueueOpHead &h, const char *reason) {
  h.outcome = OP_REJECTED;
  strncpy(h.reason, reason, sizeof(h.reason) - 1);
  h.reason[sizeof(h.reason) - 1] = '\0';
}

static const char *jsonStr(JsonVariantConst v) {
  const char *s = v.as<const char *>();
  return s ? s : "";
}

// Text the PLC can store in a user record: no control characters, DEL, '|'
// (the BLE ADD_USER separator) or 0x1F (the NVS record separator), 1..max bytes.
static bool cleanText(const char *s, size_t max) {
  size_t n = strlen(s);
  if (n == 0 || n > max) return false;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; p++) {
    if (*p < 0x20 || *p == 0x7F || *p == '|') return false;
  }
  return true;
}

static bool b64urlChar(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

// "$p1$" + 16 base64url + "$" + 32 base64url (password_hash.h).
static bool passwordHashShape(const char *s) {
  if (strlen(s) != (size_t)USER_HASH_LEN || strncmp(s, "$p1$", 4) != 0 || s[20] != '$') return false;
  for (int i = 4; i < USER_HASH_LEN; i++) {
    if (i != 20 && !b64urlChar(s[i])) return false;
  }
  return true;
}

// Walks one page of a queue: fills `page` and calls `take(key, value)` for each
// entry the PLC should look at (not the cursor, not already rejected) while
// there is room. `take` returns false if it did not use a slot.
template <class Take>
static bool walkPage(const char *body, const char *skipKey, int maxOps, QueuePage &page, Take take) {
  memset(&page, 0, sizeof(page));
  if (!body) return false;

  JsonDocument doc;
  if (deserializeJson(doc, body)) return false;   // IncompleteInput: the reply did not fit
  page.parsed = true;
  if (doc.isNull()) return true;                  // "null": the queue is empty
  if (!doc.is<JsonObjectConst>()) {
    page.parsed = false;
    return false;
  }

  for (JsonPairConst kv : doc.as<JsonObjectConst>()) {
    const char *key = kv.key().c_str();
    page.keys++;
    if (strlen(key) > (size_t)QUEUE_KEY_MAX) {
      page.keyTooLong = true;
      continue;
    }
    if (!page.haveLast || cloudRtdbKeyCompare(key, page.lastKey) > 0) {
      strcpy(page.lastKey, key);
      page.haveLast = true;
    }
    if (skipKey && strcmp(key, skipKey) == 0) continue;
    JsonVariantConst v = kv.value();
    if (strcmp(jsonStr(v["status"]), "rejected") == 0) continue;   // waits for the web app to queue it again
    if (page.ops >= maxOps) continue;
    if (take(key, v)) page.ops++;
  }
  return true;
}

// Sets h.action from the entry; false (and rejected) if the action is unknown.
static bool readAction(QueueOpHead &h, JsonVariantConst v) {
  const char *action = jsonStr(v["action"]);
  if (strcmp(action, "remove") == 0) {
    h.action = OP_REMOVE;
  } else if (action[0] == '\0' || strcmp(action, "add") == 0) {
    h.action = OP_ADD;
  } else {
    rejectOp(h, "Unknown action");
    return false;
  }
  return true;
}

bool cloudParsePhoneQueue(const char *body, const char *skipKey, PhoneOp *ops, int maxOps, QueuePage &page) {
  return walkPage(body, skipKey, maxOps, page, [&](const char *key, JsonVariantConst v) {
    PhoneOp &op = ops[page.ops];
    memset(&op, 0, sizeof(op));
    strcpy(op.h.key, key);
    op.h.outcome = OP_PENDING;
    if (!readAction(op.h, v)) return true;

    // The exact id the phone sends at login; the key only when the entry has none.
    const char *rawId = jsonStr(v["phoneId"]);
    if (!rawId[0]) rawId = key;
    char id[QUEUE_KEY_MAX + 1];
    copyTrimmed(id, sizeof(id), rawId);
    if (!id[0]) {
      rejectOp(op.h, "Phone ID missing");
      return true;
    }
    if (strlen(id) > (size_t)PHONE_ID_MAX) {
      rejectOp(op.h, "Phone ID longer than 40 characters");
      return true;
    }
    strcpy(op.phoneId, id);

    // The PLC keeps one owner field, shown as "Owner email" on its page.
    char owner[sizeof(op.owner)];
    copyTrimmed(owner, sizeof(owner), jsonStr(v["ownerEmail"]));
    if (!owner[0]) copyTrimmed(owner, sizeof(owner), jsonStr(v["owner"]));
    strcpy(op.owner, owner);
    return true;
  });
}

bool cloudParseUserQueue(const char *body, const char *skipKey, UserOp *ops, int maxOps, QueuePage &page) {
  return walkPage(body, skipKey, maxOps, page, [&](const char *key, JsonVariantConst v) {
    UserOp &op = ops[page.ops];
    memset(&op, 0, sizeof(op));
    strcpy(op.h.key, key);
    op.h.outcome = OP_PENDING;
    if (!readAction(op.h, v)) return true;

    char email[QUEUE_KEY_MAX + 1];
    copyTrimmed(email, sizeof(email), jsonStr(v["email"]));
    if (!email[0]) {
      rejectOp(op.h, "Email missing");
      return true;
    }
    if (!cleanText(email, sizeof(op.email) - 1) || !strchr(email, '@')) {
      rejectOp(op.h, "Email not valid");
      return true;
    }
    strcpy(op.email, email);
    if (op.h.action == OP_REMOVE) return true;

    char name[QUEUE_KEY_MAX + 1];
    copyTrimmed(name, sizeof(name), jsonStr(v["name"]));
    if (!cleanText(name, sizeof(op.name) - 1)) {
      rejectOp(op.h, "Name missing or not valid");
      return true;
    }
    strcpy(op.name, name);

    const char *role = jsonStr(v["role"]);
    if (strcmp(role, "Admin") != 0 && strcmp(role, "Operator") != 0) {
      rejectOp(op.h, "Role must be Admin or Operator");
      return true;
    }
    strcpy(op.role, role);

    const char *access = jsonStr(v["accessType"]);
    if (strcmp(access, "timed") == 0) {
      JsonVariantConst s = v["startTs"], e = v["endTs"];
      if (!s.is<uint32_t>() || !e.is<uint32_t>() || s.as<uint32_t>() == 0 || e.as<uint32_t>() <= s.as<uint32_t>()) {
        rejectOp(op.h, "Timed access needs From before To");
        return true;
      }
      op.accessType = 1;
      op.startTs = s.as<uint32_t>();
      op.endTs   = e.as<uint32_t>();
    } else if (access[0] == '\0' || strcmp(access, "perpetual") == 0) {
      op.accessType = 0;
    } else {
      rejectOp(op.h, "Unknown access type");
      return true;
    }

    const char *hash = jsonStr(v["passwordHash"]);
    if (hash[0] && !passwordHashShape(hash)) {
      rejectOp(op.h, "Password hash not valid");
      return true;
    }
    strcpy(op.passwordHash, hash);

    char from[QUEUE_KEY_MAX + 1];
    copyTrimmed(from, sizeof(from), jsonStr(v["renameFrom"]));
    if (from[0] && !cleanText(from, sizeof(op.renameFrom) - 1)) {
      rejectOp(op.h, "Previous email not valid");
      return true;
    }
    strcpy(op.renameFrom, from);
    return true;
  });
}

size_t cloudBuildQueueResult(char *out, size_t cap, const void *ops, size_t stride, int n, int &written) {
  written = 0;
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  const unsigned char *p = static_cast<const unsigned char *>(ops);
  for (int i = 0; i < n; i++, p += stride) {
    const QueueOpHead &h = *reinterpret_cast<const QueueOpHead *>(p);
    if (h.outcome == OP_PENDING) continue;
    if (written > 0) o.raw(",");
    if (h.outcome == OP_REJECTED) {
      o.pathField(h.key, "status");
      o.raw("\"rejected\",");
      o.pathField(h.key, "reason");
      o.utf8Value(h.reason);
    } else {
      o.pathField(h.key, nullptr);
      o.raw("null");
    }
    written++;
  }
  o.raw("}");
  if (!o.ok) {
    written = 0;
    return 0;
  }
  return o.len;
}

size_t cloudBuildPhonelistPatch(char *out, size_t cap, const PhoneOp *ops, int n) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  for (int i = 0; i < n; i++) {
    const PhoneOp &op = ops[i];
    if (i > 0) o.raw(",");
    if (op.h.action == OP_REMOVE) {
      o.pathField(op.h.key, nullptr);
      o.raw("null");
      continue;
    }
    o.pathField(op.h.key, "phoneId");
    o.utf8Value(op.phoneId);
    if (op.owner[0]) {
      o.raw(",");
      o.pathField(op.h.key, strchr(op.owner, '@') ? "ownerEmail" : "owner");
      o.utf8Value(op.owner);
    }
    o.raw(",");
    o.pathField(op.h.key, "source");
    o.raw("\"plc\",");
    o.pathField(op.h.key, "registeredAt");
    o.raw("{\".sv\":\"timestamp\"}");
  }
  o.raw("}");
  return o.ok ? o.len : 0;
}

size_t cloudBuildUserlistPatch(char *out, size_t cap, const UserOp *ops, int n) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  for (int i = 0; i < n; i++) {
    const UserOp &op = ops[i];
    if (i > 0) o.raw(",");
    o.pathField(op.h.key, nullptr);
    if (op.h.action == OP_REMOVE) {
      o.raw("null");
      continue;
    }
    o.raw("{\"email\":");
    o.utf8Value(op.email);
    o.raw(",\"name\":");
    o.utf8Value(op.name);
    o.raw(",");
    o.plainString("role", op.role);
    o.raw(",");
    o.plainString("accessType", op.accessType == 1 ? "timed" : "perpetual");
    o.raw(",");
    o.plainUint("startTs", op.accessType == 1 ? op.startTs : 0);
    o.raw(",");
    o.plainUint("endTs", op.accessType == 1 ? op.endTs : 0);
    o.raw(",\"source\":\"plc\",\"updatedAt\":{\".sv\":\"timestamp\"}}");
  }
  o.raw("}");
  return o.ok ? o.len : 0;
}

size_t cloudBuildDeleteKeys(char *out, size_t cap, const char *const *keys, int n) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  for (int i = 0; i < n; i++) {
    if (i > 0) o.raw(",");
    o.pathField(keys[i], nullptr);
    o.raw("null");
  }
  o.raw("}");
  return o.ok ? o.len : 0;
}

bool cloudParseNetworkRequest(const char *body, NetworkRequest &req) {
  memset(&req, 0, sizeof(req));
  if (!body) return false;
  JsonDocument doc;
  if (deserializeJson(doc, body)) return false;
  if (doc.isNull()) return true;   // nothing queued
  if (!doc.is<JsonObjectConst>()) return false;
  JsonObjectConst o = doc.as<JsonObjectConst>();
  req.present  = true;
  req.rejected = strcmp(jsonStr(o["status"]), "rejected") == 0;

  auto fail = [&](const char *why) {
    req.valid = false;
    strncpy(req.reason, why, sizeof(req.reason) - 1);
    return true;
  };
  char ble[QUEUE_KEY_MAX + 1], ssid[QUEUE_KEY_MAX + 1], pass[QUEUE_KEY_MAX + 1];
  copyTrimmed(ble, sizeof(ble), jsonStr(o["bleName"]));
  copyTrimmed(ssid, sizeof(ssid), jsonStr(o["ssid"]));
  copyTrimmed(pass, sizeof(pass), jsonStr(o["wifiPassword"]));
  // The limits of the PLC's own Network Settings page (handleNetConfigPost()).
  size_t bl = strlen(ble), sl = strlen(ssid), pl = strlen(pass);
  if (bl < 5 || bl > 10 || strncmp(ble, "RRC_", 4) != 0) return fail("BLE name must start with RRC_, 5-10 characters");
  if (sl < 5 || sl > 10) return fail("Wi-Fi SSID must be 5-10 characters");
  if (pl != 0 && (pl < 8 || pl > 10)) return fail("Wi-Fi password must be 8-10 characters");
  for (const char *s : {(const char *)ble, (const char *)ssid, (const char *)pass}) {
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; p++) {
      if (*p < 0x20 || *p == 0x7F) return fail("Control characters are not allowed");
    }
  }
  strcpy(req.bleName, ble);
  strcpy(req.ssid, ssid);
  strcpy(req.wifiPassword, pass);
  req.valid = true;
  return true;
}

size_t cloudBuildSyncRecord(char *out, size_t cap, const char *type, const char *deviceId, const char *ts,
                            const char *status, const SyncCounts &c) {
  Out o = {out, cap, 0, cap > 0};
  o.raw("{");
  o.plainString("type", type);
  o.raw(",");
  o.plainString("status", status);
  o.raw(",");
  o.plainUint("entries", (unsigned long)c.entries);
  o.raw(",");
  o.plainUint("added", (unsigned long)c.added);
  o.raw(",");
  o.plainUint("updated", (unsigned long)c.updated);
  o.raw(",");
  o.plainUint("removed", (unsigned long)c.removed);
  o.raw(",");
  o.plainUint("rejected", (unsigned long)c.rejected);
  o.raw(",");
  o.plainString("ts", ts);
  o.raw(",");
  o.plainString("deviceId", deviceId);
  o.raw("}");
  return o.ok ? o.len : 0;
}

void cloudHistoryKey(const char *ts, unsigned long uptimeS, char *out, size_t cap) {
  if (cap == 0) return;
  if (!ts || !ts[0]) {
    snprintf(out, cap, "uptime-%lu", uptimeS);
    return;
  }
  size_t i = 0;
  for (; ts[i] && i + 1 < cap; i++) {
    char c = ts[i];
    out[i] = c == ':' ? '-' : (c == ' ' ? '_' : c);
  }
  out[i] = '\0';
}

// ---------------- event upload ----------------

bool cloudEventKey(const char *ts, unsigned seq, char *out, size_t cap) {
  if (cap > 0) out[0] = '\0';
  if (!ts || strlen(ts) != 19 || seq > 99) return false;
  // "YYYY-MM-DD HH:MM:SS"
  static const char kShape[] = "dddd-dd-dd dd:dd:dd";
  for (size_t i = 0; i < 19; i++) {
    bool digit = ts[i] >= '0' && ts[i] <= '9';
    if (kShape[i] == 'd' ? !digit : ts[i] != kShape[i]) return false;
  }
  int month = (ts[5] - '0') * 10 + (ts[6] - '0');
  int day   = (ts[8] - '0') * 10 + (ts[9] - '0');
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  int n = snprintf(out, cap, "%.10s_%.2s-%.2s-%.2s_%02u", ts, ts + 11, ts + 14, ts + 17, seq);
  if (n <= 0 || (size_t)n >= cap) {
    if (cap > 0) out[0] = '\0';
    return false;
  }
  return true;
}

size_t cloudBuildRootPath(char *out, size_t cap, const char *secret) {
  if (cap == 0) return 0;
  out[0] = '\0';
  if (!cloudValidDbSecret(secret)) return 0;
  int n = snprintf(out, cap, "/.json?auth=%s", secret);
  if (n > 0 && (size_t)n < cap) return (size_t)n;
  memset(out, 0, cap);   // a cut-off path still held part of the secret
  return 0;
}

// "node/deviceId/YYYY-MM/key": the field name of one event in the root PATCH.
static void eventPath(Out &o, const char *node, const char *deviceId, const char *key) {
  o.raw("\"");
  o.raw(node);
  o.raw("/");
  o.raw(deviceId);
  o.raw("/");
  char month[8];
  memcpy(month, key, 7);
  month[7] = '\0';
  o.raw(month);
  o.raw("/");
  o.raw(key);
  o.raw("\":");
}

size_t cloudBuildEventsPatch(char *out, size_t cap, const char *deviceId, const CloudLogEntry *logs, int nLogs,
                             const CloudAccessEntry *acc, int nAcc) {
  if (!cloudValidDeviceId(deviceId) || nLogs + nAcc <= 0) return 0;
  Out o = {out, cap, 0, cap > 0};
  bool first = true;
  o.raw("{");
  for (int i = 0; i < nLogs; i++) {
    const CloudLogEntry &e = logs[i];
    if (strlen(e.key) < 7) return 0;
    if (!first) o.raw(",");
    first = false;
    eventPath(o, "bfa_logs", deviceId, e.key);
    o.raw("{");
    o.plainString("plc_ts", e.ts);
    o.raw(",");
    o.plainString("category", e.category);
    o.raw(",\"detail\":");
    o.utf8Value(e.detail);
    if (e.skipped) {
      o.raw(",");
      o.plainUint("skipped", e.skipped);
    }
    o.raw(",\"uploadedAt\":{\".sv\":\"timestamp\"}}");
  }
  for (int i = 0; i < nAcc; i++) {
    const CloudAccessEntry &e = acc[i];
    if (strlen(e.key) < 7) return 0;
    if (!first) o.raw(",");
    first = false;
    eventPath(o, "bfa_events", deviceId, e.key);
    o.raw("{");
    o.plainUint("auth", e.authorized ? 1 : 0);
    o.raw(",\"email\":");
    o.utf8Value(e.email);
    o.raw(",\"username\":");
    o.utf8Value(e.name);
    o.raw(",");
    o.plainString("role", e.role);
    o.raw(",\"empId\":");
    o.utf8Value(e.empId);
    o.raw(",\"phoneId\":");
    o.utf8Value(e.phoneId);
    o.raw(",");
    o.plainString("reason", e.reason);
    o.raw(",");
    o.plainString("plc_ts", e.ts);
    if (e.suppressed) {
      o.raw(",");
      o.plainUint("suppressed", e.suppressed);
    }
    o.raw(",\"uploadedAt\":{\".sv\":\"timestamp\"}}");
  }
  o.raw("}");
  return o.ok ? o.len : 0;
}
