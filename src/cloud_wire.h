// Text formats of the cloud heartbeat (IntelliKran docs/PLC_SYNC_API.md): the
// JSON sent to Firebase and the replies read back. No Arduino or network
// dependencies, so it can be compiled and tested on a PC.
#pragma once

#include <stddef.h>
#include <stdint.h>

// What the PLC reports. Filled by loop() (see publishCloudStatus() in
// main.cpp) except ip and uptimeS, which the network task adds.
struct CloudStatus {
  char     ip[16];
  uint32_t uptimeS;
  uint32_t freeHeap;      // bytes, at the moment of the push (network task)
  uint32_t minFreeHeap;   // lowest since boot
  char     rtc[20];       // "YYYY-MM-DD HH:MM:SS", empty when the clock is unset
  bool     rtcOk;
  bool     sdOk;
  bool     estop;         // true while the E-STOP is engaged (firmware's motionEstop)
  bool     up, down, left, right;
  bool     bleConn;
  bool     bleAuth;
  char     bleUser[64];
  // Network settings in use (the web app's Network Settings form shows them).
  char     bleName[32];
  char     wifiSsid[32];
  bool     netRestartPending;   // new settings saved, applied at the next idle restart
};

// Both return the length written, or 0 if it did not fit in `cap`.
size_t cloudBuildSignIn(char *out, size_t cap, const char *login, const char *key);
size_t cloudBuildHeartbeat(char *out, size_t cap, const char *projectId, const char *plcId,
                           const char *fw, const CloudStatus &s);

// The status code from "HTTP/1.x NNN ...", or 0 if `resp` is not a reply.
int cloudHttpStatus(const char *resp);

// Copies a string field from the JSON body of `resp` (the first match at any
// depth). False if it is absent, truncated, or does not fit in `cap`.
bool cloudJsonString(const char *resp, const char *key, char *out, size_t cap);

// `^[a-z0-9][a-z0-9-]*$`, 3-32 chars: what the cloud allows as a PLC ID.
bool cloudValidPlcId(const char *s);

// Letters, digits, '-' and '_' only, 1-64 chars. The API key goes into a URL.
bool cloudValidApiKey(const char *s);

// ---- Realtime Database push (the "Firebase" page of the local web panel) ----
// The web app registers a BLE Face Access device under a Firestore auto-ID and
// the PLC writes to the Realtime Database record `devices/{deviceId}`.

// The Firestore document ID pasted from the web app. Letters, digits, '-' and
// '_', 1-32 chars: nothing a Realtime Database key or a URL would treat specially.
bool cloudValidDeviceId(const char *s);

// A legacy database secret. Letters, digits, '-', '_' and '.', 1-64 chars: it
// goes into a URL query, so nothing that would need escaping is allowed.
bool cloudValidDbSecret(const char *s);

// Extracts the host from the Realtime Database URL ("https://x.firebaseio.com",
// a trailing '/' and a missing scheme are fine). Only Google's own database
// domains are accepted, because the secret is sent to this host. False if the
// URL is not one, or the host does not fit in `cap`.
bool cloudParseDbHost(const char *url, char *host, size_t cap);

// "/devices/{deviceId}.json?auth={secret}". Every Realtime Database path the
// PLC uses is built here or by cloudBuildDbPath(), from the saved Device ID.
// 0 if it did not fit.
size_t cloudBuildDevicePath(char *out, size_t cap, const char *deviceId, const char *secret);

// "/devices/{deviceId}/{child}.json?{query}&auth={secret}". `child` is one of
// the PLC's own fixed node names (not escaped); empty means the device record
// itself. `query` is already URL-encoded and may be empty. 0 if it did not fit.
size_t cloudBuildDbPath(char *out, size_t cap, const char *deviceId, const char *child, const char *query,
                        const char *secret);

// Percent-encodes everything but A-Z a-z 0-9 - _ . ~ (for a URL query value).
// 0 if it did not fit (an empty input also returns 0, with out = "").
size_t cloudUrlEncode(const char *in, char *out, size_t cap);

// The body of an HTTP reply (after the blank line), or nullptr if there is none.
const char *cloudHttpBody(const char *resp);

// The JSON for a PATCH of `devices/{deviceId}`: the heartbeat (PLC-local time, as
// the web app's online indicator reads it), its interval, the live status and
// the network settings in use. `heartbeat` is left out while the PLC's clock is
// unset, so the device shows as offline instead of fresh. 0 if it did not fit.
size_t cloudBuildDeviceUpdate(char *out, size_t cap, const char *fw, unsigned heartbeatIntervalS,
                              const CloudStatus &s);

// ---- Sync with the web app (BLE Face Access section) ----
// The web app queues changes for the PLC below devices/{deviceId}, with
// devices/{deviceId}/tobesynced = true as the wake-up flag (same as the MA
// devices). The PLC deletes a queue entry once it has applied it, or marks it
// {status: "rejected", reason}.
//
//   tobesyncedphoneid/{key}  {phoneId, phoneModel, owner?, ownerEmail?, queuedAt}
//                            | {phoneId, action: "remove", queuedAt}
//   tobesyncedusers/{key}    {email, name, role, accessType, startTs, endTs,
//                             passwordHash?, renameFrom?, queuedAt}
//                            | {email, action: "remove", queuedAt}
//   tobesyncednetwork        {bleName, ssid, wifiPassword?, queuedAt}
//
// and the PLC mirrors what it holds into phonelist/{key} and userlist/{key}.

static const int PHONE_ID_MAX  = 40;    // Device::id in web_handler.h
static const int QUEUE_KEY_MAX = 127;   // longest queue key the PLC can address
static const int PHONE_KEY_MAX = QUEUE_KEY_MAX;

enum QueueAction : uint8_t { OP_ADD = 0, OP_REMOVE = 1 };

// What applying one entry did. OP_PENDING = not applied (yet): the entry stays.
enum QueueOutcome : uint8_t {
  OP_PENDING = 0,
  OP_ADDED,      // new on the PLC
  OP_UPDATED,    // already there, changed
  OP_UNCHANGED,  // already there, nothing to change
  OP_REMOVED,
  OP_ABSENT,     // removal of something the PLC did not have
  OP_REJECTED,   // see `reason`; the entry stays, marked rejected
};

// Common head of every queue op: the RTDB key and what became of the entry.
struct QueueOpHead {
  char    key[QUEUE_KEY_MAX + 1];
  uint8_t action;    // QueueAction
  uint8_t outcome;   // QueueOutcome
  char    reason[48];
};

struct PhoneOp {
  QueueOpHead h;
  char        phoneId[PHONE_ID_MAX + 1];
  char        owner[64];   // Device::owner: the owner email, else the owner name
};

// User fields, as in User (web_handler.h).
static const int USER_NAME_MAX  = 32;
static const int USER_EMAIL_MAX = 40;
static const int USER_HASH_LEN  = 53;   // "$p1$" + 16 + "$" + 32, see password_hash.h

struct UserOp {
  QueueOpHead h;
  char        email[64];
  char        name[64];
  char        role[16];            // "Admin" | "Operator"
  uint8_t     accessType;          // ACCESS_PERPETUAL (0) | ACCESS_TIMED (1)
  uint32_t    startTs, endTs;      // timed only: PLC wall-clock seconds
  char        passwordHash[64];    // "" = keep the current password
  char        renameFrom[64];      // "" = not a rename; else the user's current email
};

// The RTDB key of a phone id, exactly as the web app's BfaPhone.keyFor():
// trimmed, and . $ # [ ] / and control characters replaced by '_' (also DEL and
// invalid UTF-8 bytes, which no key may hold). False if empty or too long.
bool cloudPhoneKey(const char *phoneId, char *out, size_t cap);

// The RTDB key of a user, exactly as the web app's BfaUser.keyFor(): the email
// trimmed and ASCII-lower-cased, with % . $ # [ ] / control characters, DEL and
// invalid UTF-8 bytes written as %XX (so distinct emails never share a key).
// False if empty or too long.
bool cloudUserKey(const char *email, char *out, size_t cap);

// Realtime Database key order for orderBy="$key": keys that are 32-bit
// integers first, by value, then the rest by byte order. <0, 0 or >0.
int cloudRtdbKeyCompare(const char *a, const char *b);

struct QueuePage {
  bool parsed;                       // false: not JSON, or cut off (reply too big)
  int  keys;                         // children in the reply, `skipKey` included
  int  ops;                          // entries put in `ops`
  bool haveLast;
  bool keyTooLong;                   // a key longer than QUEUE_KEY_MAX was skipped
  char lastKey[QUEUE_KEY_MAX + 1];   // greatest key in the reply, for the next page
};
typedef QueuePage PhoneQueuePage;

// Parse one page of a queue. Entries already marked rejected, and `skipKey`
// (the previous page's last key, as startAt includes it), are left out. An
// entry the PLC cannot take is returned with outcome OP_REJECTED and a
// reason; the others are OP_PENDING. False if `page.parsed` is false.
bool cloudParsePhoneQueue(const char *body, const char *skipKey, PhoneOp *ops, int maxOps, QueuePage &page);
bool cloudParseUserQueue(const char *body, const char *skipKey, UserOp *ops, int maxOps, QueuePage &page);

// The PATCH of a queue that confirms `n` ops (each `stride` bytes apart,
// starting with a QueueOpHead): applied entries are deleted, rejected ones get
// status and reason, pending ones are left alone. `written` is how many entries
// it covers (0: nothing to send). 0 if it did not fit.
size_t cloudBuildQueueResult(char *out, size_t cap, const void *ops, size_t stride, int n, int &written);

// The PATCH of phonelist for phones registered (OP_ADD) or deleted
// (OP_REMOVE) on the PLC. Adds write single fields, so a model or name the web
// app keeps is not lost. Keys must all differ. 0 if it did not fit.
size_t cloudBuildPhonelistPatch(char *out, size_t cap, const PhoneOp *ops, int n);

// The PATCH of userlist: OP_ADD writes the whole record (never a password),
// OP_REMOVE deletes it. Keys must all differ. 0 if it did not fit.
size_t cloudBuildUserlistPatch(char *out, size_t cap, const UserOp *ops, int n);

// A PATCH that deletes `n` children of a node, by key. 0 if it did not fit.
size_t cloudBuildDeleteKeys(char *out, size_t cap, const char *const *keys, int n);

// Network settings queued by the web app. `present` false: nothing queued.
struct NetworkRequest {
  bool present;
  bool rejected;          // already marked rejected: waits for a new request
  bool valid;
  char reason[48];        // when !valid
  char bleName[32];
  char ssid[32];
  char wifiPassword[64];  // "" = keep the current one
};
// Parses GET tobesyncednetwork.json and checks it against the PLC's rules
// (BLE name "RRC_" + 5-10 characters, SSID 5-10, Wi-Fi password 8-10). False
// if the reply is not complete JSON.
bool cloudParseNetworkRequest(const char *body, NetworkRequest &req);

struct SyncCounts {
  int entries;    // queue entries confirmed (all outcomes but OP_PENDING)
  int added;
  int updated;
  int removed;    // removed, or already absent
  int rejected;
};
typedef SyncCounts PhoneSyncCounts;

// The synchistory record of one sync run (the web app reads status, entries
// and ts). `type` is "phones", "users" or "network". 0 if it did not fit.
size_t cloudBuildSyncRecord(char *out, size_t cap, const char *type, const char *deviceId, const char *ts,
                            const char *status, const SyncCounts &c);

// synchistory key: "YYYY-MM-DD_HH-MM-SS" from the PLC time, or "uptime-N"
// while the clock is unset (the MA devices use the same keys).
void cloudHistoryKey(const char *ts, unsigned long uptimeS, char *out, size_t cap);
