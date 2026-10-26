// BLE message format v1 (JSON) for the login, user-management and event-log
// characteristics.
//
// This file is the whole wire format of those three channels and nothing else:
// no Arduino, BLE or flash calls, only ArduinoJson and the standard library, so
// it compiles and is tested on a PC (test/host/ble_protocol_test.cpp). main.cpp
// decides what a message MEANS; this decides what it LOOKS like.
//
// Every message is one JSON object, UTF-8, sent inside the usual AES-GCM
// packet:
//     {"v":1,"t":"<type>", ...named fields...}
//   v  protocol version, an integer, 1 for everything below
//   t  message type; a reply carries the type of its request
// Unknown extra fields are ignored. A request whose "v" is not 1 is refused
// with error BAD_VERSION, one that is not valid JSON of the right shape with
// BAD_FORMAT. Replies to a failed request carry "ok":false and an "error" code.
//
// The older pipe/CSV format ("email|password|deviceid", "ADD_USER|...",
// "LOG_DAY|...", "AUTH_OK|Operator", ...) is still accepted, and answered in
// kind, so phones and PLCs on either side of this change keep working:
// isJson() tells the two apart, and the reply always uses the request's format.
// The motion, status and heartbeat characteristics are NOT part of this; they
// are the E-STOP path and keep their compact CSV.
//
// Messages (see PROJECT_DOCUMENTATION.txt section 8.1 for the full tables):
//   login        {"v":1,"t":"login","email":..,"password":..,"deviceId":..}
//                -> {"v":1,"t":"login","ok":true,"role":"Admin"|"Operator"}
//                -> {"v":1,"t":"login","ok":false,"error":CODE}
//   session.end  PLC -> app, {"v":1,"t":"session.end","reason":"OUT_OF_TIME"}
//   user.add     {"v":1,"t":"user.add","id":101,"name":..,"email":..,
//                 "password":..,"role":"Operator","access":"perpetual"|"timed",
//                 "from":"YYYY-MM-DDTHH:MM","to":".."}      (from/to for timed)
//                -> {"v":1,"t":"user.add","id":101,"ok":true}
//                -> {"v":1,"t":"user.add","id":101,"ok":false,"error":CODE}
//   log.months   {"v":1,"t":"log.months"}
//                -> log.month {"month":"YYYY-MM"} ... then log.end {"count":n}
//   log.dates    {"v":1,"t":"log.dates","month":"YYYY-MM"}
//                -> log.date {"date":"YYYY-MM-DD","size":n} ... log.end {"count":n}
//   log.day      {"v":1,"t":"log.day","date":"YYYY-MM-DD","from":1}   (from optional)
//                -> log.line {"seq":n,"ts":..,"cat":..,"detail":..} ...
//                   then log.end {"lastSeq":n,"more":true|false}
//   log.fail     {"v":1,"t":"log.fail","error":CODE}   (any log request)
#pragma once

#include <ArduinoJson.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace blep {

constexpr int kVersion = 1;

// The most plaintext the reply encryption takes (encryptAESGCM_packet).
constexpr size_t kMaxPlain = 200;

enum class ParseError : uint8_t {
  None,
  BadFormat,   // not JSON, not an object, wrong "t", or a field missing/mistyped
  BadVersion,  // a well-formed envelope whose "v" is not kVersion
};

// ---------------------------------------------------------------- detection

// Whether [plain] is a JSON message: an object, '{' first and '}' last, ignoring
// surrounding whitespace and the NUL padding of a decrypted block. The legacy
// formats never start with '{' (an email could, but it would also have to end
// the whole request with '}', which a "email|password|deviceid" line cannot do
// unless the device id does).
inline bool isJson(const std::string &plain) {
  size_t b = 0, e = plain.size();
  while (b < e && (plain[b] == ' ' || plain[b] == '\t' || plain[b] == '\r' || plain[b] == '\n')) b++;
  while (e > b && (plain[e - 1] == ' ' || plain[e - 1] == '\t' || plain[e - 1] == '\r' ||
                   plain[e - 1] == '\n' || plain[e - 1] == '\0')) e--;
  return e - b >= 2 && plain[b] == '{' && plain[e - 1] == '}';
}

namespace detail {

// Parses [plain] and checks the envelope. On success [doc] holds the object.
inline bool envelope(const std::string &plain, JsonDocument &doc, ParseError &err) {
  DeserializationError de = deserializeJson(doc, plain);
  if (de || !doc.is<JsonObject>()) { err = ParseError::BadFormat; return false; }
  JsonObjectConst o = doc.as<JsonObjectConst>();
  JsonVariantConst v = o["v"];
  if (!v.is<int>()) { err = ParseError::BadFormat; return false; }
  if (v.as<int>() != kVersion) { err = ParseError::BadVersion; return false; }
  return true;
}

// The message type, or an empty string if "t" is missing or not a string.
inline std::string typeOf(JsonObjectConst o) {
  JsonVariantConst t = o["t"];
  return t.is<const char *>() ? std::string(t.as<const char *>()) : std::string();
}

inline bool str(JsonObjectConst o, const char *key, std::string &out) {
  JsonVariantConst v = o[key];
  if (!v.is<const char *>()) return false;
  out = v.as<const char *>();
  return true;
}

inline std::string dump(const JsonDocument &doc) {
  std::string s;
  serializeJson(doc, s);
  return s;
}

// {"v":1,"t":<type>} to add the rest of a message to.
inline void begin(JsonDocument &doc, const char *type) {
  doc["v"] = kVersion;
  doc["t"] = type;
}

}  // namespace detail

// -------------------------------------------------------------------- login

struct LoginRequest {
  std::string email, password, deviceId;
};

inline ParseError parseLogin(const std::string &plain, LoginRequest &out) {
  JsonDocument doc;
  ParseError err = ParseError::None;
  if (!detail::envelope(plain, doc, err)) return err;
  JsonObjectConst o = doc.as<JsonObjectConst>();
  if (detail::typeOf(o) != "login" || !detail::str(o, "email", out.email) ||
      !detail::str(o, "password", out.password) || !detail::str(o, "deviceId", out.deviceId)) {
    return ParseError::BadFormat;
  }
  return ParseError::None;
}

// The error code a refused login is answered with, from the reason the PLC
// itself records (BAD_EMAIL, BAD_PASSWORD, OUT_OF_TIME, UNTRUSTED_DEVICE,
// INVALID_ROLE). With [revealWhich] false, a wrong email and a wrong password
// are both just BAD_CREDENTIALS (see AUTH_REPLY_NAMES_BAD_CREDENTIAL).
inline const char *loginErrorCode(const char *reason, bool revealWhich) {
  if (!revealWhich && (strcmp(reason, "BAD_EMAIL") == 0 || strcmp(reason, "BAD_PASSWORD") == 0)) {
    return "BAD_CREDENTIALS";
  }
  return reason;
}

inline std::string loginOk(const char *role) {
  JsonDocument doc;
  detail::begin(doc, "login");
  doc["ok"] = true;
  doc["role"] = role;
  return detail::dump(doc);
}

inline std::string loginFail(const char *error) {
  JsonDocument doc;
  detail::begin(doc, "login");
  doc["ok"] = false;
  doc["error"] = error;
  return detail::dump(doc);
}

// The legacy replies: "AUTH_OK" (Admin), "AUTH_OK|Operator", and for a refusal
// "AUTH_FAIL:<code>" for the codes the legacy format has, else plain
// "AUTH_FAIL" (BAD_CREDENTIALS, INVALID_ROLE, BAD_FORMAT, BAD_VERSION).
inline std::string loginOkLegacy(const char *role) {
  if (strcmp(role, "Admin") == 0) return "AUTH_OK";
  if (strcmp(role, "Operator") == 0) return "AUTH_OK|Operator";
  return "AUTH_FAIL";  // a role the legacy format cannot say is never a success
}

inline std::string loginFailLegacy(const char *error) {
  if (strcmp(error, "BAD_EMAIL") == 0 || strcmp(error, "BAD_PASSWORD") == 0 ||
      strcmp(error, "OUT_OF_TIME") == 0 || strcmp(error, "UNTRUSTED_DEVICE") == 0) {
    return std::string("AUTH_FAIL:") + error;
  }
  return "AUTH_FAIL";
}

// PLC -> app, unprompted: the signed-in session is over.
inline std::string sessionEnd(const char *reason) {
  JsonDocument doc;
  detail::begin(doc, "session.end");
  doc["reason"] = reason;
  return detail::dump(doc);
}

// ------------------------------------------------------------------ user.add

// The fields of ADD_USER, in the form the validation in main.cpp already
// takes: [id] decimal digits, [access] "P" / "T" (anything else is for the
// validation to refuse as BAD_ACCESS), [from] / [to] empty unless sent.
struct AddUserRequest {
  std::string id, name, email, password, role, access, from, to;
};

// [replyId] is the id to echo in a failure: the request's own once it has been
// read, else 0.
inline ParseError parseAddUser(const std::string &plain, AddUserRequest &out, uint32_t &replyId) {
  replyId = 0;
  JsonDocument doc;
  ParseError err = ParseError::None;
  if (!detail::envelope(plain, doc, err)) return err;
  JsonObjectConst o = doc.as<JsonObjectConst>();
  if (detail::typeOf(o) != "user.add") return ParseError::BadFormat;

  JsonVariantConst idv = o["id"];
  if (!idv.is<uint32_t>()) return ParseError::BadFormat;
  uint32_t id = idv.as<uint32_t>();
  if (id < 1 || id > 999999999u) return ParseError::BadFormat;  // 1-9 digits, like the legacy reqId
  replyId = id;
  out.id = std::to_string(id);

  std::string access;
  if (!detail::str(o, "name", out.name) || !detail::str(o, "email", out.email) ||
      !detail::str(o, "password", out.password) || !detail::str(o, "role", out.role) ||
      !detail::str(o, "access", access)) {
    return ParseError::BadFormat;
  }
  out.access = (access == "perpetual") ? "P" : (access == "timed") ? "T" : access;

  // from / to: a string, or absent / null.
  JsonVariantConst fv = o["from"];
  JsonVariantConst tv = o["to"];
  if (fv.is<const char *>()) out.from = fv.as<const char *>(); else if (!fv.isNull()) return ParseError::BadFormat;
  if (tv.is<const char *>()) out.to = tv.as<const char *>(); else if (!tv.isNull()) return ParseError::BadFormat;
  return ParseError::None;
}

inline std::string addUserOk(uint32_t id) {
  JsonDocument doc;
  detail::begin(doc, "user.add");
  doc["id"] = id;
  doc["ok"] = true;
  return detail::dump(doc);
}

inline std::string addUserFail(uint32_t id, const char *error) {
  JsonDocument doc;
  detail::begin(doc, "user.add");
  doc["id"] = id;
  doc["ok"] = false;
  doc["error"] = error;
  return detail::dump(doc);
}

// ----------------------------------------------------------------- event log

enum class LogOp : uint8_t { Months, Dates, Day };

// [arg] is the month (Dates) or the day (Day) exactly as sent: main.cpp checks
// it against its own YYYY-MM / YYYY-MM-DD rules, the only way a file is named.
struct LogRequest {
  LogOp op = LogOp::Months;
  std::string arg;
  uint32_t from = 1;  // Day only: the first line wanted
};

inline ParseError parseLogRequest(const std::string &plain, LogRequest &out) {
  JsonDocument doc;
  ParseError err = ParseError::None;
  if (!detail::envelope(plain, doc, err)) return err;
  JsonObjectConst o = doc.as<JsonObjectConst>();
  const std::string type = detail::typeOf(o);
  if (type == "log.months") {
    out.op = LogOp::Months;
  } else if (type == "log.dates") {
    out.op = LogOp::Dates;
    if (!detail::str(o, "month", out.arg)) return ParseError::BadFormat;
  } else if (type == "log.day") {
    out.op = LogOp::Day;
    if (!detail::str(o, "date", out.arg)) return ParseError::BadFormat;
    JsonVariantConst fv = o["from"];
    if (!fv.isNull()) {
      // 1 to 9,999,999, as many digits as the legacy fromSeq allows.
      if (!fv.is<uint32_t>()) return ParseError::BadFormat;
      uint32_t from = fv.as<uint32_t>();
      if (from < 1 || from > 9999999u) return ParseError::BadFormat;
      out.from = from;
    }
  } else {
    return ParseError::BadFormat;
  }
  return ParseError::None;
}

inline std::string logMonth(const std::string &month) {
  JsonDocument doc;
  detail::begin(doc, "log.month");
  doc["month"] = month;
  return detail::dump(doc);
}

inline std::string logDate(const std::string &date, uint32_t size) {
  JsonDocument doc;
  detail::begin(doc, "log.date");
  doc["date"] = date;
  doc["size"] = size;
  return detail::dump(doc);
}

// End of a month or day listing.
inline std::string logEnd(uint32_t count) {
  JsonDocument doc;
  detail::begin(doc, "log.end");
  doc["count"] = count;
  return detail::dump(doc);
}

// End of a day's lines: the last line number read, and whether more follow.
inline std::string logEndDay(uint32_t lastSeq, bool more) {
  JsonDocument doc;
  detail::begin(doc, "log.end");
  doc["lastSeq"] = lastSeq;
  doc["more"] = more;
  return detail::dump(doc);
}

inline std::string logFail(const char *error) {
  JsonDocument doc;
  detail::begin(doc, "log.fail");
  doc["error"] = error;
  return detail::dump(doc);
}

// One stored log line, "YYYY-MM-DD HH:MM:SS,CATEGORY,detail", as named fields.
// A line not in that shape is sent whole as "raw". The result never exceeds
// [maxPlain] bytes: a long detail is cut (never through a UTF-8 sequence) and
// ends in "...".
inline std::string logLine(uint32_t seq, const std::string &stored, size_t maxPlain = kMaxPlain) {
  const size_t c1 = stored.find(',');
  const size_t c2 = (c1 == std::string::npos) ? std::string::npos : stored.find(',', c1 + 1);
  const bool structured = (c2 != std::string::npos);
  const std::string ts = structured ? stored.substr(0, c1) : std::string();
  const std::string cat = structured ? stored.substr(c1 + 1, c2 - c1 - 1) : std::string();
  std::string text = structured ? stored.substr(c2 + 1) : stored;

  auto build = [&](const std::string &body) -> std::string {
    JsonDocument doc;
    detail::begin(doc, "log.line");
    doc["seq"] = seq;
    if (structured) {
      doc["ts"] = ts;
      doc["cat"] = cat;
      doc["detail"] = body;
    } else {
      doc["raw"] = body;
    }
    return detail::dump(doc);
  };

  std::string out = build(text);
  // Escaped characters take more than one byte, so cut by the overshoot and
  // look again.
  while (out.size() > maxPlain && text.size() > 3) {
    const size_t over = out.size() - maxPlain;
    size_t keep = (text.size() > over + 3) ? text.size() - over - 3 : 0;
    while (keep > 0 && (static_cast<unsigned char>(text[keep]) & 0xC0) == 0x80) keep--;
    text = text.substr(0, keep) + "...";
    out = build(text);
  }
  return out;
}

}  // namespace blep
