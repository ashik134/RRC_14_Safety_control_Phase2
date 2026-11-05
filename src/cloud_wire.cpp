#include "cloud_wire.h"

#include <stdio.h>
#include <string.h>

namespace {

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
  if (!cloudValidDeviceId(deviceId) || !cloudValidDbSecret(secret)) return 0;
  int n = snprintf(out, cap, "/devices/%s.json?auth=%s", deviceId, secret);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
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

  o.field("status");
  o.raw("{");
  o.plainUint("uptimeS", s.uptimeS);
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
  o.plainBool("bleConn", s.bleConn);
  o.raw(",");
  o.plainBool("bleAuth", s.bleAuth);
  o.raw(",");
  o.plainString("bleUser", s.bleUser);
  o.raw("}}");
  return o.ok ? o.len : 0;
}
