#include "cloud_link.h"

#include <Ethernet.h>
#include <Dns.h>
#include <Dhcp.h>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>

#include "cloud_roots.h"
#include "eth_diag.h"
#include "web_handler.h"   // FIRMWARE_VERSION

// The Firebase project is chosen at build time, in platformio.ini build_flags:
//   -DCLOUD_PROJECT_ID=\"your-project-id\"
// There is no default: a build without it never connects to any project.
#ifdef CLOUD_PROJECT_ID
static const char *PROJECT_ID  = CLOUD_PROJECT_ID;
static const char *COMMIT_PATH = "/v1/projects/" CLOUD_PROJECT_ID "/databases/(default)/documents:commit";
#else
static const char *PROJECT_ID  = nullptr;
static const char *COMMIT_PATH = nullptr;
#endif

// The web app shows Offline after 90 s of silence, so a failed heartbeat is
// retried well inside that window: one lost report must not flip the status.
static const unsigned long HEARTBEAT_MS   = 60000;
static const unsigned long RETRY_MIN_MS   = 10000;
static const unsigned long RETRY_MAX_MS   = 300000;
static const unsigned long DHCP_RETRY_MS  = 30000;
static const unsigned long HEAP_RETRY_MS  = 5000;
// The ID token lasts an hour; signing in again costs one more TLS session.
static const unsigned long TOKEN_LIFE_MS  = 50UL * 60UL * 1000UL;

static const uint16_t      DNS_TIMEOUT_MS    = 3000;
static const uint16_t      TCP_TIMEOUT_MS    = 4000;
static const uint32_t      TLS_READ_MS       = 5000;
static const unsigned long SESSION_BUDGET_MS = 20000;

// This firmware has crashed on low heap before (see setup()), so a session
// starts only when it can finish and still leave the BLE, Wi-Fi and web stacks
// room. mbedTLS allocates two ~16.7 KB record buffers, plus the handshake:
// about 50 KB in all, of which the largest single block is one record buffer.
// When memory is short the PLC reports nothing rather than risk a crash. A
// configured PLC idles at 72-74 KB, measured on the bench with NimBLE, so this
// leaves it room to report and still keeps about 18 KB in reserve. Each report
// prints the lowest heap reached, which is what to check this figure against.
static const uint32_t TLS_MIN_FREE_HEAP = 68000;
static const uint32_t TLS_MIN_LARGEST   = 20000;

static const char *AUTH_HOST      = "identitytoolkit.googleapis.com";
static const char *FIRESTORE_HOST = "firestore.googleapis.com";

struct Creds {
  char plcId[33];
  char login[97];
  char key[65];
  char apiKey[65];
};

// Shared with loop() (publish, panel) and always copied under `mux`.
static portMUX_TYPE  mux            = portMUX_INITIALIZER_UNLOCKED;
static Creds         savedCreds     = {};
static bool          credsChanged   = false;
static CloudStatus   sharedStatus   = {};
static char          sharedState[96] = "Not configured";
static uint32_t      okCount        = 0;
static uint32_t      failCount      = 0;
static bool          everOk         = false;
static unsigned long lastOkMs       = 0;

// Allocated only once a login is configured, so an unconfigured PLC keeps this
// memory and never parses the certificates.
struct Buffers {
  char token[2048];
  char body[1536];
  char resp[4096];
};
static Buffers          *mem = nullptr;
static mbedtls_x509_crt  roots;

static Creds creds = {};   // the network task's own copy

// Realtime Database push: same pattern, its own settings and counters. Never
// log or show `secret`: it is a key to the whole database.
static FirebaseSettings fbSaved       = {};
static bool             fbChanged     = false;
static char             fbState[96]   = "Not configured";
static uint32_t         fbOkCount     = 0;
static uint32_t         fbFailCount   = 0;
static bool             fbEverOk      = false;
static unsigned long    fbLastOkMs    = 0;

static FirebaseSettings fb = {};       // the network task's own copy
static char             fbHost[80] = "";

// Pushed to the web app as devices/{id}/heartbeatIntervalSec: it treats the PLC
// as offline after this plus 60 s of silence.
static const unsigned FB_HEARTBEAT_S = 60;

// ---- phone list sync (see cloud_link.h) ----
// Every request is a TLS session of its own (~50 KB of heap, 1-3 s), so the
// flag is polled at a modest rate and the queue is read a few entries at a time.
static const unsigned long PH_POLL_MS      = 20000;   // tobesynced poll
static const unsigned long PH_RETRY_MS     = 30000;   // after a failed request
static const unsigned long PH_NEXT_MS      = 1000;    // between the jobs of one sync
static const unsigned long PH_LOOP_WAIT_MS = 30000;   // for loop() to pick up a job
static const int           PH_PAGE         = 4;       // queue entries per GET (fits mem->resp)
static const int           PH_PAGES_PER_GO = 5;       // then let the heartbeat run
static const int           PH_PATCH_BATCH  = 3;       // phonelist changes per PATCH (fits mem->body)
static const int           PH_OUTBOX       = 4;       // local-page changes waiting to be sent

// Local web page changes for phonelist, oldest first. Shared with loop(), under `mux`.
struct PhoneChange {
  char phoneId[PHONE_ID_MAX + 1];
  char owner[64];
  bool removed;
};
static PhoneChange   phOutbox[PH_OUTBOX];
static int           phOutboxCount    = 0;
static bool          phOutboxOverflow = false;   // a change was dropped: compare the lists again

static char          phState[96]  = "Not started";
static bool          phEverOk     = false;
static unsigned long phLastOkMs   = 0;

// The network task's own sync state.
static bool          phReconcilePending = true;   // compare phonelist with the registry (once per boot)
static bool          phPassPending      = true;   // read the queue (once at boot, then when tobesynced)
static bool          phPassActive       = false;  // a pass is under way: phCursor and phCounts are live
static bool          phClearFlag        = false;  // tobesynced was true: set it false before reading
static unsigned long phNextPollMs       = 0;
static unsigned long phNextWorkMs       = 0;
static char          phCursor[PHONE_KEY_MAX + 1] = "";
static PhoneSyncCounts phCounts         = {};
static int           phPageSize         = PH_PAGE;

// Work handed to loop()'s task, which owns devices[]. One job at a time: the
// network task sets it Requested; loop() takes it (Serving), does it and sets
// Done. The network task gives up only on a job loop() has not taken, so the
// buffer is never freed while loop() uses it.
enum : uint8_t { JOB_IDLE, JOB_REQUESTED, JOB_SERVING, JOB_DONE };
enum : uint8_t { JOB_APPLY, JOB_SNAPSHOT };
struct LocalPhone {
  char id[PHONE_ID_MAX + 1];
  char owner[64];
};
static volatile uint8_t jobState  = JOB_IDLE;
static uint8_t          jobKind   = JOB_APPLY;
static void            *jobBuf    = nullptr;
static int              jobCount  = 0;
static int              jobResult = 0;

static void setStateIn(char *dst, size_t cap, const char *tag, const char *fmt, va_list ap) {
  char msg[96];
  vsnprintf(msg, sizeof(msg), fmt, ap);

  taskENTER_CRITICAL(&mux);
  bool changed = strcmp(msg, dst) != 0;
  if (changed) memcpy(dst, msg, cap);
  taskEXIT_CRITICAL(&mux);
  if (changed) Serial.printf("[%s] %s\n", tag, msg);
}

static void setState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(sharedState, sizeof(sharedState), "CLOUD", fmt, ap);
  va_end(ap);
}

static void setFbState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(fbState, sizeof(fbState), "FIREBASE", fmt, ap);
  va_end(ap);
}

static void setPhState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(phState, sizeof(phState), "PHONESYNC", fmt, ap);
  va_end(ap);
}

// ---------------- mbedTLS transport over EthernetClient ----------------
// Same transport as src/spike/tls_spike.cpp, which proved it on this board.

struct Bio {
  EthernetClient *tcp;
  unsigned long   startMs;
};

static int bioSend(void *ctx, const unsigned char *buf, size_t len) {
  Bio *b = static_cast<Bio *>(ctx);
  size_t n = b->tcp->write(buf, len);   // bounded by the W5500 retransmission limit
  return n > 0 ? (int)n : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bioRecv(void *ctx, unsigned char *buf, size_t len, uint32_t timeoutMs) {
  Bio *b = static_cast<Bio *>(ctx);
  unsigned long t0 = millis();
  for (;;) {
    int avail = b->tcp->available();
    if (avail > 0) {
      int n = b->tcp->read(buf, len < (size_t)avail ? len : (size_t)avail);
      return n > 0 ? n : MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (!b->tcp->connected()) return MBEDTLS_ERR_NET_CONN_RESET;
    if (millis() - t0 >= timeoutMs || millis() - b->startMs >= SESSION_BUDGET_MS) return MBEDTLS_ERR_SSL_TIMEOUT;
    vTaskDelay(pdMS_TO_TICKS(5));   // never spin: IDLE0 is watched by the task WDT
  }
}

static int rng(void *, unsigned char *out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

static bool sslWriteAll(mbedtls_ssl_context *ssl, const char *data, size_t len) {
  size_t off = 0;
  while (off < len) {
    int w = mbedtls_ssl_write(ssl, reinterpret_cast<const unsigned char *>(data) + off, len - off);
    if (w <= 0) return false;
    off += (size_t)w;
  }
  return true;
}

// One complete HTTPS request (POST, or PATCH for the Realtime Database).
// HTTP/1.0 keeps the reply simple: no chunked encoding, and the server closes
// the connection at the end. The whole reply lands in mem->resp, NUL-terminated.
// Returns the HTTP status, or 0 with `stage` naming the step that failed. The
// certificate is always verified, so the device key, token and database secret
// only ever go to Google.
static int httpsRequest(const char *method, const char *host, const char *path, const char *bearer, const char *body, const char *&stage) {
  mem->resp[0] = '\0';

  stage = "DNS lookup";
  IPAddress ip;
  DNSClient dns;
  dns.begin(Ethernet.dnsServerIP());
  if (dns.getHostByName(host, ip, DNS_TIMEOUT_MS) != 1) return 0;

  stage = "TCP connect";
  EthernetClient tcp;
  tcp.setConnectionTimeout(TCP_TIMEOUT_MS);
  if (!tcp.connect(ip, 443)) {
    tcp.stop();
    return 0;
  }

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config  conf;
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  Bio bio = {&tcp, millis()};

  stage = "TLS setup";
  int err = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (err == 0) {
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &roots, nullptr);
    mbedtls_ssl_conf_rng(&conf, rng, nullptr);
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);  // TLS 1.2+
    mbedtls_ssl_conf_read_timeout(&conf, TLS_READ_MS);
    err = mbedtls_ssl_setup(&ssl, &conf);
  }
  if (err == 0) err = mbedtls_ssl_set_hostname(&ssl, host);

  if (err == 0) {
    mbedtls_ssl_set_bio(&ssl, &bio, bioSend, nullptr, bioRecv);
    stage = "TLS handshake";
    do {
      err = mbedtls_ssl_handshake(&ssl);
    } while (err == MBEDTLS_ERR_SSL_WANT_READ || err == MBEDTLS_ERR_SSL_WANT_WRITE);
  }

  int status = 0;
  if (err == 0) {
    stage = "HTTP request";
    // The Realtime Database path carries the secret, and a queue page also its
    // query (up to ~384 bytes, see fbRequest()). Wiped below: it holds the secret.
    char head[640];
    size_t bodyLen = strlen(body);
    int n = snprintf(head, sizeof(head),
                     "%s %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: plc14\r\nContent-Type: application/json\r\n"
                     "Content-Length: %u\r\nConnection: close\r\n",
                     method, path, host, (unsigned)bodyLen);
    bool sent = n > 0 && (size_t)n < sizeof(head) && sslWriteAll(&ssl, head, (size_t)n);
    if (sent && bearer) {
      sent = sslWriteAll(&ssl, "Authorization: Bearer ", 22) && sslWriteAll(&ssl, bearer, strlen(bearer)) &&
             sslWriteAll(&ssl, "\r\n", 2);
    }
    if (sent) sent = sslWriteAll(&ssl, "\r\n", 2) && sslWriteAll(&ssl, body, bodyLen);
    memset(head, 0, sizeof(head));

    if (sent) {
      stage = "HTTP reply";
      size_t got = 0;
      while (got < sizeof(mem->resp) - 1 && millis() - bio.startMs < SESSION_BUDGET_MS) {
        int rd = mbedtls_ssl_read(&ssl, reinterpret_cast<unsigned char *>(mem->resp) + got, sizeof(mem->resp) - 1 - got);
        if (rd <= 0) break;
        got += (size_t)rd;
      }
      mem->resp[got] = '\0';
      status = cloudHttpStatus(mem->resp);
    }
    mbedtls_ssl_close_notify(&ssl);
  }

  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  tcp.stop();
  return status;
}

// ---------------- sign-in and heartbeat ----------------

enum class Outcome { Ok, Failed, Rejected };

// Rejected means Firebase refused the login: trying again soon cannot help and
// would only get the account rate-limited.
static Outcome signIn() {
  mem->token[0] = '\0';
  if (cloudBuildSignIn(mem->body, sizeof(mem->body), creds.login, creds.key) == 0) {
    setState("Sign-in request too long");
    return Outcome::Rejected;
  }
  char path[128];
  snprintf(path, sizeof(path), "/v1/accounts:signInWithPassword?key=%s", creds.apiKey);

  const char *stage = "";
  int status = httpsRequest("POST", AUTH_HOST, path, nullptr, mem->body, stage);
  memset(mem->body, 0, sizeof(mem->body));   // it held the device key
  if (status == 0) {
    setState("Sign-in failed at: %s", stage);
    return Outcome::Failed;
  }
  if (status != 200) {
    char why[64] = "";
    cloudJsonString(mem->resp, "message", why, sizeof(why));
    setState("Sign-in refused (HTTP %d) %s", status, why);
    return status >= 500 ? Outcome::Failed : Outcome::Rejected;
  }
  if (!cloudJsonString(mem->resp, "idToken", mem->token, sizeof(mem->token))) {
    setState("Sign-in reply had no token");
    return Outcome::Failed;
  }
  return Outcome::Ok;
}

static bool sendHeartbeat() {
  CloudStatus s;
  taskENTER_CRITICAL(&mux);
  s = sharedStatus;
  taskEXIT_CRITICAL(&mux);
  strlcpy(s.ip, Ethernet.localIP().toString().c_str(), sizeof(s.ip));
  s.uptimeS = (uint32_t)(esp_timer_get_time() / 1000000LL);

  if (cloudBuildHeartbeat(mem->body, sizeof(mem->body), PROJECT_ID, creds.plcId, FIRMWARE_VERSION, s) == 0) {
    setState("Heartbeat too long to send");
    return false;
  }

  const char *stage = "";
  int status = httpsRequest("POST", FIRESTORE_HOST, COMMIT_PATH, mem->token, mem->body, stage);
  if (status == 200) return true;
  if (status == 0) {
    setState("Heartbeat failed at: %s", stage);
    return false;
  }
  char why[64] = "";
  cloudJsonString(mem->resp, "message", why, sizeof(why));
  setState("Heartbeat refused (HTTP %d) %s", status, why);
  // A refused token may just be stale (or the key replaced): sign in afresh.
  if (status == 401 || status == 403) mem->token[0] = '\0';
  return false;
}

// Writes the heartbeat and status to devices/{deviceId} in the Realtime
// Database. PATCH merges: it never removes what the web app keeps there
// (phonelist, employees, ...). Returns Rejected when retrying soon cannot help.
static Outcome sendFirebasePush() {
  CloudStatus s;
  taskENTER_CRITICAL(&mux);
  s = sharedStatus;
  taskEXIT_CRITICAL(&mux);
  strlcpy(s.ip, Ethernet.localIP().toString().c_str(), sizeof(s.ip));
  s.uptimeS = (uint32_t)(esp_timer_get_time() / 1000000LL);

  char path[160];   // holds the secret: keep it off the heap and out of every log
  size_t pathLen = cloudBuildDevicePath(path, sizeof(path), fb.deviceId, fb.secret);
  if (pathLen == 0 || cloudBuildDeviceUpdate(mem->body, sizeof(mem->body), FIRMWARE_VERSION, FB_HEARTBEAT_S, s) == 0) {
    memset(path, 0, sizeof(path));
    setFbState("Settings invalid or status too long to send");
    return Outcome::Rejected;
  }

  const char *stage = "";
  int status = httpsRequest("PATCH", fbHost, path, nullptr, mem->body, stage);
  memset(path, 0, sizeof(path));
  if (status == 200) return Outcome::Ok;
  if (status == 0) {
    setFbState("Push failed at: %s", stage);
    return Outcome::Failed;
  }

  char why[64] = "";
  cloudJsonString(mem->resp, "error", why, sizeof(why));
  if (status == 401 || status == 403) {
    setFbState("Database secret refused (HTTP %d) %s", status, why);
    return Outcome::Rejected;
  }
  if (status == 404) {
    setFbState("Database not found (HTTP 404): check the Database URL");
    return Outcome::Rejected;
  }
  setFbState("Push refused (HTTP %d) %s", status, why);
  return status >= 500 ? Outcome::Failed : Outcome::Rejected;
}

// ---------------- phone list sync ----------------

static bool tlsHeapOk() { return ESP.getFreeHeap() >= TLS_MIN_FREE_HEAP && ESP.getMaxAllocHeap() >= TLS_MIN_LARGEST; }

// One Realtime Database request below devices/{deviceId}; the reply lands in
// mem->resp. Returns the HTTP status, or 0 with `stage` naming what failed.
static int fbRequest(const char *method, const char *child, const char *query, const char *body, const char *&stage) {
  char path[384];   // holds the secret: keep it off the heap and out of every log
  if (cloudBuildDbPath(path, sizeof(path), fb.deviceId, child, query, fb.secret) == 0) {
    stage = "building the request";
    return 0;
  }
  int status = httpsRequest(method, fbHost, path, nullptr, body, stage);
  memset(path, 0, sizeof(path));
  return status;
}

// Ok: go on. Retry: a request failed, try again in a while. Heap: not enough
// memory for TLS right now. Rejected: the database refused us; retrying soon
// cannot help (the heartbeat shows the same problem).
enum class PhRes { Ok, Retry, Heap, Rejected };

static PhRes phFailed(const char *what, int status, const char *stage) {
  if (status == 0) {
    setPhState("%s failed at: %s", what, stage);
    return PhRes::Retry;
  }
  if (status == 401 || status == 403) {
    setPhState("%s refused (HTTP %d): check the database secret", what, status);
    return PhRes::Rejected;
  }
  if (status == 404) {
    setPhState("%s: database not found (HTTP 404)", what);
    return PhRes::Rejected;
  }
  setPhState("%s refused (HTTP %d)", what, status);
  return status >= 500 ? PhRes::Retry : PhRes::Rejected;
}

static void phMarkOk() {
  taskENTER_CRITICAL(&mux);
  phEverOk   = true;
  phLastOkMs = millis();
  taskEXIT_CRITICAL(&mux);
}

// Runs a job on loop()'s task (see cloudLinkLoop()) and waits for it. False if
// loop() did not take it within PH_LOOP_WAIT_MS: it is then withdrawn, so
// `buf` is the caller's again either way.
static bool runOnLoop(uint8_t kind, void *buf, int count, int &result) {
  taskENTER_CRITICAL(&mux);
  jobKind   = kind;
  jobBuf    = buf;
  jobCount  = count;
  jobResult = 0;
  jobState  = JOB_REQUESTED;
  taskEXIT_CRITICAL(&mux);

  unsigned long t0 = millis();
  for (;;) {
    bool late = millis() - t0 >= PH_LOOP_WAIT_MS;
    taskENTER_CRITICAL(&mux);
    uint8_t st = jobState;
    if (st == JOB_DONE) {
      result   = jobResult;
      jobState = JOB_IDLE;
      jobBuf   = nullptr;
    } else if (st == JOB_REQUESTED && late) {
      jobState = JOB_IDLE;   // loop() never saw it: safe to take back
      jobBuf   = nullptr;
      st       = JOB_IDLE;
    }
    taskEXIT_CRITICAL(&mux);
    if (st == JOB_DONE) return true;
    if (st == JOB_IDLE) return false;
    vTaskDelay(pdMS_TO_TICKS(10));   // JOB_SERVING ends on its own: loop() is doing it now
  }
}

static void tally(const PhoneOp &op) {
  if (op.outcome == PHONE_PENDING) return;
  phCounts.entries++;
  switch (op.outcome) {
    case PHONE_ADDED:    phCounts.added++; break;
    case PHONE_UPDATED:  phCounts.updated++; break;
    case PHONE_REMOVED:
    case PHONE_ABSENT:   phCounts.removed++; break;
    case PHONE_REJECTED: phCounts.rejected++; break;
    default: break;
  }
}

// Sends `n` phonelist changes in one PATCH. PhRes::Ok also when the database
// refused them as invalid: they are dropped rather than retried forever.
static PhRes sendPhonelistOps(const PhoneOp *ops, int n) {
  if (cloudBuildPhonelistPatch(mem->body, sizeof(mem->body), ops, n) == 0) {
    setPhState("A phone change was too long to send; dropped");
    return PhRes::Ok;
  }
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("PATCH", "phonelist", "", mem->body, stage);
  if (st == 200) {
    phMarkOk();
    return PhRes::Ok;
  }
  if (st == 400) {
    setPhState("Web phone list refused a change (HTTP 400); dropped");
    return PhRes::Ok;
  }
  return phFailed("Updating the web phone list", st, stage);
}

// After each boot, and when a local change could not be queued: every phone in
// the registry that the web list is missing is added to it (source "plc").
// Phones only the web app has are left alone: they may still be in the queue.
struct ReconcileBufs {
  LocalPhone local[MAX_DEVICES];
  char       keys[MAX_DEVICES][PHONE_ID_MAX + 1];
  bool       present[MAX_DEVICES];
  PhoneOp    ops[PH_PATCH_BATCH];
};

static PhRes phoneReconcileWith(ReconcileBufs &b) {
  int n = 0;
  if (!runOnLoop(JOB_SNAPSHOT, b.local, MAX_DEVICES, n)) {
    setPhState("Waiting for the PLC main loop");
    return PhRes::Retry;
  }
  int m = 0;   // phones with a usable key, packed to the front
  for (int i = 0; i < n; i++) {
    if (!cloudPhoneKey(b.local[i].id, b.keys[m], sizeof(b.keys[m]))) continue;
    if (m != i) b.local[m] = b.local[i];
    m++;
  }
  if (m == 0) {
    setPhState("No phones on the PLC to add to the web list");
    return PhRes::Ok;
  }

  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("GET", "phonelist", "shallow=true", "", stage);
  if (st != 200) return phFailed("Reading the web phone list", st, stage);
  if (!cloudShallowHasKeys(cloudHttpBody(mem->resp), b.keys, m, b.present)) {
    setPhState("Web phone list too long to compare; skipped");
    return PhRes::Ok;   // later local changes are still sent one by one
  }
  phMarkOk();

  int added = 0;
  int i = 0;
  while (i < m) {
    int k = 0;
    for (; i < m && k < PH_PATCH_BATCH; i++) {
      if (b.present[i]) continue;
      PhoneOp &op = b.ops[k++];
      memset(&op, 0, sizeof(op));
      strlcpy(op.key, b.keys[i], sizeof(op.key));
      strlcpy(op.phoneId, b.local[i].id, sizeof(op.phoneId));
      strlcpy(op.owner, b.local[i].owner, sizeof(op.owner));
      op.action = PHONE_ADD;
    }
    if (k == 0) break;
    PhRes r = sendPhonelistOps(b.ops, k);
    if (r != PhRes::Ok) return r;   // the whole comparison is repeated next time
    added += k;
  }
  if (added) setPhState("Added %d PLC phone(s) to the web list", added);
  else setPhState("Web phone list has every PLC phone");
  return PhRes::Ok;
}

static PhRes phoneReconcile() {
  ReconcileBufs *b = static_cast<ReconcileBufs *>(malloc(sizeof(ReconcileBufs)));
  if (!b) return PhRes::Heap;
  PhRes r = phoneReconcileWith(*b);
  free(b);
  return r;
}

// Sends the oldest local-page changes to phonelist.
static PhRes phoneFlushOutbox() {
  PhoneChange batch[PH_PATCH_BATCH];
  int k;
  bool overflow;
  taskENTER_CRITICAL(&mux);
  k = phOutboxCount < PH_PATCH_BATCH ? phOutboxCount : PH_PATCH_BATCH;
  memcpy(batch, phOutbox, sizeof(PhoneChange) * k);
  overflow = phOutboxOverflow;
  phOutboxOverflow = false;
  taskEXIT_CRITICAL(&mux);
  if (overflow) phReconcilePending = true;
  if (k == 0) return PhRes::Ok;

  PhoneOp *ops = static_cast<PhoneOp *>(malloc(sizeof(PhoneOp) * PH_PATCH_BATCH));
  if (!ops) return PhRes::Heap;
  int used = 0;   // outbox entries this batch covers
  int nOps = 0;
  for (; used < k; used++) {
    PhoneOp &op = ops[nOps];
    memset(&op, 0, sizeof(op));
    if (!cloudPhoneKey(batch[used].phoneId, op.key, sizeof(op.key))) continue;   // no key: nothing to send
    bool again = false;   // the same phone twice: its later change goes in the next PATCH
    for (int j = 0; j < nOps; j++) again = again || strcmp(ops[j].key, op.key) == 0;
    if (again) break;
    strlcpy(op.phoneId, batch[used].phoneId, sizeof(op.phoneId));
    strlcpy(op.owner, batch[used].owner, sizeof(op.owner));
    op.action = batch[used].removed ? PHONE_REMOVE : PHONE_ADD;
    nOps++;
  }

  PhRes r = nOps > 0 ? sendPhonelistOps(ops, nOps) : PhRes::Ok;
  free(ops);
  if (r != PhRes::Ok) return r;

  // Only loop() appends, and only at the end, so the front is still ours.
  taskENTER_CRITICAL(&mux);
  memmove(phOutbox, phOutbox + used, sizeof(PhoneChange) * (phOutboxCount - used));
  phOutboxCount -= used;
  taskEXIT_CRITICAL(&mux);
  if (nOps > 0) setPhState("Sent %d phone change(s) to the web list", nOps);
  return PhRes::Ok;
}

static PhRes phonePoll() {
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("GET", "tobesynced", "", "", stage);
  if (st != 200) return phFailed("Checking for a sync request", st, stage);
  phMarkOk();
  const char *body = cloudHttpBody(mem->resp);
  if (body && strncmp(body, "true", 4) == 0) {
    phClearFlag   = true;
    phPassPending = true;
    setPhState("Sync requested by the web app");
  } else {
    setPhState("Up to date");
  }
  return PhRes::Ok;
}

// How the current pass fell short. Stuck: it cannot read past some entry, so it
// is not retried until the next request. Unsaved: the registry could not be
// stored, so the pass is retried after PH_RETRY_MS.
static bool phStuck   = false;
static bool phUnsaved = false;

// One page of the queue: read it, apply it on loop(), confirm it. `done` once
// the end of the queue is reached.
static PhRes phonePage(PhoneOp *ops, bool &done) {
  if (!tlsHeapOk()) return PhRes::Heap;

  // orderBy="$key" (no index needed). startAt includes the cursor, so one more
  // is asked for and the cursor itself is skipped.
  bool hasCursor = phCursor[0] != '\0';
  int limit = hasCursor ? phPageSize + 1 : phPageSize;
  char query[200];   // with the rest of the path this stays inside fbRequest()'s 384 bytes
  int qn = snprintf(query, sizeof(query), "orderBy=%%22%%24key%%22&limitToFirst=%d", limit);
  if (hasCursor) {
    char quoted[PHONE_KEY_MAX * 2 + 3];   // the cursor as a JSON string
    size_t q = 0;
    quoted[q++] = '"';
    for (const char *c = phCursor; *c; c++) {
      if (*c == '"' || *c == '\\') quoted[q++] = '\\';
      quoted[q++] = *c;
    }
    quoted[q++] = '"';
    quoted[q] = '\0';
    char enc[sizeof(query)];
    if (cloudUrlEncode(quoted, enc, sizeof(enc)) == 0 ||
        snprintf(query + qn, sizeof(query) - qn, "&startAt=%s", enc) >= (int)(sizeof(query) - qn)) {
      setPhState("A queue key is too long to read past");
      phStuck = true;
      done = true;
      return PhRes::Ok;
    }
  }

  const char *stage = "";
  int st = fbRequest("GET", "tobesyncedphoneid", query, "", stage);
  if (st != 200) return phFailed("Reading the sync queue", st, stage);

  PhoneQueuePage pg;
  if (!cloudParsePhoneQueue(cloudHttpBody(mem->resp), hasCursor ? phCursor : nullptr, ops, PH_PAGE + 1, pg)) {
    if (phPageSize > 1) {
      phPageSize = 1;   // the page did not fit in the reply buffer: one entry at a time
      return PhRes::Ok;
    }
    setPhState("A queue entry is too large to read");
    phStuck = true;
    done = true;
    return PhRes::Ok;
  }
  if (pg.keyTooLong) setPhState("Skipped a queue key longer than %d characters", PHONE_KEY_MAX);

  if (pg.ops > 0) {
    int unused = 0;
    if (!runOnLoop(JOB_APPLY, ops, pg.ops, unused)) {
      setPhState("Waiting for the PLC main loop");
      return PhRes::Retry;   // nothing was applied: the same page is read again
    }
    // Applied. If confirming fails the entries stay and the page is read again;
    // applying them twice changes nothing.
    int confirmable = 0;
    for (int i = 0; i < pg.ops; i++) confirmable += ops[i].outcome != PHONE_PENDING;
    int written = 0;
    size_t len = cloudBuildQueueResult(mem->body, sizeof(mem->body), ops, pg.ops, written);
    if (confirmable > 0 && len == 0) {
      setPhState("Queue result too long to send");
      return PhRes::Retry;
    }
    if (written > 0) {
      if (!tlsHeapOk()) return PhRes::Heap;
      st = fbRequest("PATCH", "tobesyncedphoneid", "", mem->body, stage);
      if (st != 200) return phFailed("Confirming queue entries", st, stage);
    }
    for (int i = 0; i < pg.ops; i++) tally(ops[i]);
    if (confirmable < pg.ops) phUnsaved = true;   // left pending: the registry could not be stored
  }
  phMarkOk();

  if (pg.keys < limit || !pg.haveLast) {
    done = true;
    return PhRes::Ok;
  }
  if (hasCursor && strcmp(pg.lastKey, phCursor) == 0) {
    // A full page that ends at the cursor again: only unreadable keys after it.
    setPhState("Cannot read past queue key %.40s", phCursor);
    phStuck = true;
    done = true;
    return PhRes::Ok;
  }
  strlcpy(phCursor, pg.lastKey, sizeof(phCursor));
  phPageSize = PH_PAGE;
  return PhRes::Ok;
}

// Logs the pass in synchistory, if it did anything, and decides whether to
// run another: a pass that applied something is followed by one more, which
// picks up whatever the web app queued meanwhile (and anything paged past).
static PhRes phoneFinishPass() {
  phPassActive = false;
  const PhoneSyncCounts c = phCounts;
  bool applied = c.entries - c.rejected > 0;
  // Unsaved entries are still in the queue: try them again in a while.
  PhRes next = phUnsaved ? PhRes::Retry : PhRes::Ok;
  phPassPending = phUnsaved || (applied && !phStuck);

  if (phUnsaved) setPhState("Could not save the phone list on the PLC; retrying");
  if (c.entries == 0) {
    if (!phStuck && !phUnsaved) setPhState("Up to date");
    return next;
  }
  const char *status = (phStuck || phUnsaved) ? "incomplete" : (c.rejected > 0 ? "partial" : "success");
  if (!phStuck && !phUnsaved)
    setPhState("Synced: %d added, %d updated, %d removed, %d rejected", c.added, c.updated, c.removed, c.rejected);

  char ts[20];
  taskENTER_CRITICAL(&mux);
  memcpy(ts, sharedStatus.rtc, sizeof(ts));
  taskEXIT_CRITICAL(&mux);
  char key[24];
  cloudHistoryKey(ts, (unsigned long)(esp_timer_get_time() / 1000000LL), key, sizeof(key));
  char child[48];
  snprintf(child, sizeof(child), "synchistory/%s", key);
  if (cloudBuildPhoneSyncRecord(mem->body, sizeof(mem->body), fb.deviceId, ts, status, c) == 0) return next;

  // The history is a log, not state: a failed write is not retried.
  if (!tlsHeapOk()) return next;
  const char *stage = "";
  int st = fbRequest("PUT", child, "", mem->body, stage);
  if (st != 200) Serial.printf("[PHONESYNC] Sync history not written (HTTP %d %s)\n", st, st ? "" : stage);
  return next;
}

static PhRes phonePass() {
  if (!phPassActive) {
    if (phClearFlag) {
      // Cleared before the queue is read: anything queued from now on sets it again.
      if (!tlsHeapOk()) return PhRes::Heap;
      const char *stage = "";
      int st = fbRequest("PUT", "tobesynced", "", "false", stage);
      if (st != 200) return phFailed("Clearing tobesynced", st, stage);
      phClearFlag = false;
    }
    phPassActive = true;
    phStuck      = false;
    phUnsaved    = false;
    phCursor[0]  = '\0';
    phCounts     = {};
    phPageSize   = PH_PAGE;
    setPhState("Reading the sync queue");
  }

  PhoneOp *ops = static_cast<PhoneOp *>(malloc(sizeof(PhoneOp) * (PH_PAGE + 1)));
  if (!ops) return PhRes::Heap;
  PhRes r = PhRes::Ok;
  bool done = false;
  for (int pages = 0; pages < PH_PAGES_PER_GO && !done && r == PhRes::Ok; pages++) r = phonePage(ops, done);
  free(ops);
  if (r != PhRes::Ok || !done) return r;   // the rest next time, after any heartbeat
  return phoneFinishPass();
}

static bool phoneDue(unsigned long now) {
  if ((long)(now - phNextWorkMs) < 0) return false;
  taskENTER_CRITICAL(&mux);
  bool outbox = phOutboxCount > 0 || phOutboxOverflow;
  taskEXIT_CRITICAL(&mux);
  return phReconcilePending || outbox || phPassPending || (long)(now - phNextPollMs) >= 0;
}

// One job per call, so the heartbeat is never held up for long.
static void phoneStep() {
  PhRes r;
  taskENTER_CRITICAL(&mux);
  bool outbox = phOutboxCount > 0 || phOutboxOverflow;
  taskEXIT_CRITICAL(&mux);

  if (phReconcilePending) {
    r = phoneReconcile();
    if (r == PhRes::Ok) phReconcilePending = false;
  } else if (outbox) {
    r = phoneFlushOutbox();
  } else if (phPassPending) {
    r = phonePass();
  } else {
    phNextPollMs = millis() + PH_POLL_MS;
    r = phonePoll();
  }

  unsigned long wait = PH_NEXT_MS;
  if (r == PhRes::Heap) wait = HEAP_RETRY_MS;
  else if (r == PhRes::Retry) wait = PH_RETRY_MS;
  else if (r == PhRes::Rejected) wait = RETRY_MAX_MS;
  phNextWorkMs = millis() + wait;
}

// Takes up memory the first time a configured PLC needs it.
static bool prepareTls() {
  if (mem) return true;
  Buffers *b = static_cast<Buffers *>(malloc(sizeof(Buffers)));
  if (!b) return false;
  b->token[0] = '\0';
  mbedtls_x509_crt_init(&roots);
  int err = mbedtls_x509_crt_parse(&roots, reinterpret_cast<const unsigned char *>(GTS_ROOTS_PEM), sizeof(GTS_ROOTS_PEM));
  if (err != 0) {
    mbedtls_x509_crt_free(&roots);
    free(b);
    setState("Root certificate error -0x%04X", (unsigned)(-err));
    return false;
  }
  mem = b;
  return true;
}

// ---------------- the task ----------------

// Realtime Database push is on only with a complete, valid configuration; the
// host is parsed once, when the settings arrive.
static bool fbActive() { return fb.enabled && fbHost[0] && cloudValidDeviceId(fb.deviceId) && cloudValidDbSecret(fb.secret); }

static void cloudStep() {
  static bool          netUp        = false;
  static unsigned long nextDhcpMs   = 0;
  static unsigned long nextBeatMs   = 0;
  static unsigned long nextFbMs     = 0;
  static unsigned long tokenAtMs    = 0;
  static uint32_t      failStreak   = 0;
  static uint32_t      fbFailStreak = 0;

  unsigned long now = millis();

  taskENTER_CRITICAL(&mux);
  bool changed = credsChanged;
  if (changed) {
    creds = savedCreds;
    credsChanged = false;
  }
  bool fbNew = fbChanged;
  if (fbNew) {
    fb = fbSaved;
    fbChanged = false;
  }
  taskEXIT_CRITICAL(&mux);
  if (changed) {
    if (mem) mem->token[0] = '\0';
    failStreak = 0;
    nextBeatMs = now;
  }
  if (fbNew) {
    if (!cloudParseDbHost(fb.dbUrl, fbHost, sizeof(fbHost))) fbHost[0] = '\0';
    fbFailStreak = 0;
    nextFbMs = now;
    // New settings (or boot): compare the lists and read the queue afresh.
    phReconcilePending = true;
    phPassPending      = true;
    phPassActive       = false;
    phClearFlag        = false;
    phNextPollMs       = now;
    phNextWorkMs       = now;
  }

  // Firestore needs a project in the build; the Realtime Database push does not.
  bool fsOn = PROJECT_ID && creds.plcId[0];
  bool fbOn = fbActive();
  if (!fsOn) setState("%s", creds.plcId[0] ? "No cloud project set in this build" : "Not configured");
  if (!fbOn) {
    setFbState("%s", fb.enabled ? "Settings incomplete" : (fb.deviceId[0] ? "Disabled" : "Not configured"));
    setPhState("Off: Firebase push is not enabled");
  }
  if (!fsOn && !fbOn) return;

  // Network trouble is shown on every service that is waiting for the network.
  auto netState = [&](const char *msg) {
    if (fsOn) setState("%s", msg);
    if (fbOn) {
      setFbState("%s", msg);
      setPhState("%s", msg);
    }
  };

  EthDiagStatus eth = ethDiagGetStatus();
  if (!eth.chipDetected) {
    netState("No Ethernet hardware detected");
    return;
  }
  if (!eth.linkUp) {
    netUp = false;
    netState("Ethernet cable not connected");
    return;
  }

  if (!netUp) {
    if ((long)(now - nextDhcpMs) < 0) return;
    netState("Requesting an address (DHCP)");
    netUp = ethDiagStartDhcp();
    if (!netUp) {
      nextDhcpMs = millis() + DHCP_RETRY_MS;
      netState("No DHCP server on this network");
      return;
    }
    now = millis();
  }

  bool fsDue = fsOn && (long)(now - nextBeatMs) >= 0;
  bool fbDue = fbOn && (long)(now - nextFbMs) >= 0;
  // Phone sync only fills the gaps: never in the same step as a heartbeat.
  bool phDue = fbOn && !fsDue && !fbDue && phoneDue(now);
  if (!fsDue && !fbDue && !phDue) return;

  int lease = Ethernet.maintain();
  if (lease == DHCP_CHECK_RENEW_FAIL || lease == DHCP_CHECK_REBIND_FAIL) {
    netUp = false;
    return;
  }

  if (ESP.getFreeHeap() < TLS_MIN_FREE_HEAP || ESP.getMaxAllocHeap() < TLS_MIN_LARGEST || !prepareTls()) {
    // In whole KB: a figure that moves every retry would reprint this line each time.
    char msg[96];
    snprintf(msg, sizeof(msg), "Waiting for free memory (%u KB free, %u KB largest)", (unsigned)(ESP.getFreeHeap() / 1024),
             (unsigned)(ESP.getMaxAllocHeap() / 1024));
    if (fsDue) {
      setState("%s", msg);
      nextBeatMs = now + HEAP_RETRY_MS;
    }
    if (fbDue) {
      setFbState("%s", msg);
      nextFbMs = now + HEAP_RETRY_MS;
    }
    if (phDue) {
      setPhState("%s", msg);
      phNextWorkMs = now + HEAP_RETRY_MS;
    }
    return;
  }

  if (phDue) {
    phoneStep();
    return;
  }

  // One TLS session at a time: each needs ~50 KB. Firestore first, as before.
  if (fsDue) {
    Outcome outcome = Outcome::Ok;
    if (!mem->token[0] || now - tokenAtMs >= TOKEN_LIFE_MS) {
      outcome = signIn();
      if (outcome == Outcome::Ok) tokenAtMs = millis();
    }
    if (outcome == Outcome::Ok && !sendHeartbeat()) outcome = Outcome::Failed;

    if (outcome == Outcome::Ok) {
      failStreak = 0;
      nextBeatMs = now + HEARTBEAT_MS;
      taskENTER_CRITICAL(&mux);
      okCount++;
      everOk   = true;
      lastOkMs = millis();
      taskEXIT_CRITICAL(&mux);
      setState("Connected");
      Serial.printf("[CLOUD] Report sent (heap %u free, lowest since boot %u, stack unused %u)\n", (unsigned)ESP.getFreeHeap(),
                    (unsigned)ESP.getMinFreeHeap(), (unsigned)uxTaskGetStackHighWaterMark(nullptr));
    } else {
      taskENTER_CRITICAL(&mux);
      failCount++;
      taskEXIT_CRITICAL(&mux);
      unsigned long wait = outcome == Outcome::Rejected ? RETRY_MAX_MS : RETRY_MIN_MS << (failStreak < 5 ? failStreak : 5);
      if (wait > RETRY_MAX_MS) wait = RETRY_MAX_MS;
      failStreak++;
      nextBeatMs = millis() + wait;
    }
  }

  if (fbDue && ESP.getFreeHeap() >= TLS_MIN_FREE_HEAP && ESP.getMaxAllocHeap() >= TLS_MIN_LARGEST) {
    Outcome outcome = sendFirebasePush();
    if (outcome == Outcome::Ok) {
      fbFailStreak = 0;
      nextFbMs = millis() + FB_HEARTBEAT_S * 1000UL;
      taskENTER_CRITICAL(&mux);
      fbOkCount++;
      fbEverOk   = true;
      fbLastOkMs = millis();
      taskEXIT_CRITICAL(&mux);
      setFbState("Connected");
      Serial.printf("[FIREBASE] Push sent (heap %u free, lowest since boot %u, stack unused %u)\n", (unsigned)ESP.getFreeHeap(),
                    (unsigned)ESP.getMinFreeHeap(), (unsigned)uxTaskGetStackHighWaterMark(nullptr));
    } else {
      taskENTER_CRITICAL(&mux);
      fbFailCount++;
      taskEXIT_CRITICAL(&mux);
      unsigned long wait = outcome == Outcome::Rejected ? RETRY_MAX_MS : RETRY_MIN_MS << (fbFailStreak < 5 ? fbFailStreak : 5);
      if (wait > RETRY_MAX_MS) wait = RETRY_MAX_MS;
      fbFailStreak++;
      nextFbMs = millis() + wait;
    }
  } else if (fbDue) {
    // The Firestore session just used the memory: try again shortly.
    nextFbMs = millis() + HEAP_RETRY_MS;
  }
}

static void cloudTask(void *) {
  for (;;) {
    ethDiagPoll();
    cloudStep();
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

// ---------------- public ----------------

static void loadCreds() {
  Preferences p;
  if (!p.begin("cloudlink", true)) return;   // namespace absent: never configured
  p.getString("plc", savedCreds.plcId, sizeof(savedCreds.plcId));
  p.getString("login", savedCreds.login, sizeof(savedCreds.login));
  p.getString("key", savedCreds.key, sizeof(savedCreds.key));
  p.getString("api", savedCreds.apiKey, sizeof(savedCreds.apiKey));
  p.end();
  if (!savedCreds.login[0] || !savedCreds.key[0] || !savedCreds.apiKey[0]) savedCreds.plcId[0] = '\0';
  credsChanged = true;
}

static void loadFirebase() {
  Preferences p;
  if (!p.begin("fbcfg", true)) return;   // namespace absent: never configured
  p.getString("id", fbSaved.deviceId, sizeof(fbSaved.deviceId));
  p.getString("sec", fbSaved.secret, sizeof(fbSaved.secret));
  p.getString("url", fbSaved.dbUrl, sizeof(fbSaved.dbUrl));
  fbSaved.enabled = p.getBool("en", false);
  p.end();
  fbChanged = true;
}

static volatile bool taskRunning = false;

// Started only once something is configured: the stack is 12 KB of a heap that
// can be as low as ~45 KB, which an unconfigured PLC should not have to give up.
// Core 0, lowest application priority: the layout the spike tested. The BLE
// and Wi-Fi stacks preempt it, and loop() on core 1 is never blocked by it.
static void startTask() {
  if (taskRunning) return;
  // Set first: loop() must stop using the W5500 before the task starts on it.
  // This always runs on loop()'s own task, so loop() is not mid-poll here.
  taskRunning = true;
  if (xTaskCreatePinnedToCore(cloudTask, "cloud_link", 12288, nullptr, 1, nullptr, 0) != pdPASS) {
    taskRunning = false;
    setState("Not enough memory to start");
    setFbState("Not enough memory to start");
  }
}

bool cloudLinkRunning() { return taskRunning; }

bool cloudLinkAvailable() { return PROJECT_ID != nullptr; }

void cloudLinkBegin() {
  loadCreds();
  loadFirebase();
  if (PROJECT_ID && savedCreds.plcId[0]) {
    startTask();
  } else if (savedCreds.plcId[0]) {
    // Leaves the W5500 with loop(), as on an unconfigured PLC.
    setState("No cloud project set in this build");
  }
  if (fbSaved.enabled && fbSaved.deviceId[0] && fbSaved.secret[0] && fbSaved.dbUrl[0]) startTask();
}

void cloudLinkPublish(const CloudStatus &status) {
  taskENTER_CRITICAL(&mux);
  sharedStatus = status;
  taskEXIT_CRITICAL(&mux);
}

void cloudLinkGetInfo(CloudLinkInfo &info) {
  taskENTER_CRITICAL(&mux);
  info.configured = savedCreds.plcId[0] != '\0';
  memcpy(info.plcId, savedCreds.plcId, sizeof(info.plcId));
  memcpy(info.login, savedCreds.login, sizeof(info.login));
  memcpy(info.state, sharedState, sizeof(info.state));
  info.everOk     = everOk;
  info.lastOkAgoS = everOk ? (millis() - lastOkMs) / 1000UL : 0;
  info.okCount    = okCount;
  info.failCount  = failCount;
  taskEXIT_CRITICAL(&mux);
}

bool cloudLinkSave(const String &plcId, const String &login, const String &key, const String &apiKey) {
  Preferences p;
  if (!p.begin("cloudlink", false)) return false;
  bool ok = p.putString("plc", plcId) == plcId.length() && p.putString("login", login) == login.length() &&
            p.putString("key", key) == key.length() && p.putString("api", apiKey) == apiKey.length();
  p.end();
  if (!ok) return false;

  Creds next = {};
  strlcpy(next.plcId, plcId.c_str(), sizeof(next.plcId));
  strlcpy(next.login, login.c_str(), sizeof(next.login));
  strlcpy(next.key, key.c_str(), sizeof(next.key));
  strlcpy(next.apiKey, apiKey.c_str(), sizeof(next.apiKey));
  taskENTER_CRITICAL(&mux);
  savedCreds   = next;
  credsChanged = true;
  taskEXIT_CRITICAL(&mux);
  if (PROJECT_ID) startTask();
  return true;
}

void cloudLinkClear() {
  Preferences p;
  if (p.begin("cloudlink", false)) {
    p.clear();
    p.end();
  }
  taskENTER_CRITICAL(&mux);
  memset(&savedCreds, 0, sizeof(savedCreds));
  credsChanged = true;
  taskEXIT_CRITICAL(&mux);
}

// ---------------- Realtime Database settings ----------------

void cloudLinkGetFirebase(FirebaseSettings &cfg, FirebaseInfo &info) {
  char host[80];
  taskENTER_CRITICAL(&mux);
  cfg = fbSaved;
  strlcpy(info.state, fbState, sizeof(info.state));
  info.everOk     = fbEverOk;
  info.lastOkAgoS = fbEverOk ? (millis() - fbLastOkMs) / 1000UL : 0;
  info.okCount    = fbOkCount;
  info.failCount  = fbFailCount;
  strlcpy(info.phoneState, phState, sizeof(info.phoneState));
  info.phoneEverOk     = phEverOk;
  info.phoneLastOkAgoS = phEverOk ? (millis() - phLastOkMs) / 1000UL : 0;
  taskEXIT_CRITICAL(&mux);

  info.enabled   = cfg.enabled;
  info.hasSecret = cfg.secret[0] != '\0';
  info.complete  = cloudValidDeviceId(cfg.deviceId) && cloudValidDbSecret(cfg.secret) && cloudParseDbHost(cfg.dbUrl, host, sizeof(host));
  strlcpy(info.deviceId, cfg.deviceId, sizeof(info.deviceId));
  strlcpy(info.dbUrl, cfg.dbUrl, sizeof(info.dbUrl));
}

bool cloudLinkSaveFirebase(const FirebaseSettings &next) {
  Preferences p;
  if (!p.begin("fbcfg", false)) return false;
  size_t idLen  = strlen(next.deviceId);
  size_t secLen = strlen(next.secret);
  size_t urlLen = strlen(next.dbUrl);
  bool ok = p.putString("id", next.deviceId) == idLen && p.putString("sec", next.secret) == secLen &&
            p.putString("url", next.dbUrl) == urlLen && p.putBool("en", next.enabled) == 1;
  p.end();
  if (!ok) return false;

  taskENTER_CRITICAL(&mux);
  fbSaved   = next;
  fbChanged = true;
  taskEXIT_CRITICAL(&mux);
  if (next.enabled) startTask();
  return true;
}

void cloudLinkClearFirebase() {
  Preferences p;
  if (p.begin("fbcfg", false)) {
    p.clear();
    p.end();
  }
  taskENTER_CRITICAL(&mux);
  memset(&fbSaved, 0, sizeof(fbSaved));
  fbChanged = true;
  taskEXIT_CRITICAL(&mux);
}

// ---------------- phone list sync: loop() side ----------------

void cloudLinkLoop() {
  if (jobState != JOB_REQUESTED) return;   // the usual case: one volatile read

  taskENTER_CRITICAL(&mux);
  bool mine = jobState == JOB_REQUESTED;
  if (mine) jobState = JOB_SERVING;   // from here on the network task waits for us
  uint8_t kind  = jobKind;
  void   *buf   = jobBuf;
  int     count = jobCount;
  taskEXIT_CRITICAL(&mux);
  if (!mine) return;

  int result = 0;
  if (kind == JOB_APPLY) {
    applyCloudPhoneOps(static_cast<PhoneOp *>(buf), count);
    result = count;
  } else {
    LocalPhone *out = static_cast<LocalPhone *>(buf);
    for (int i = 0; i < deviceCount && result < count; i++, result++) {
      strlcpy(out[result].id, devices[i].id, sizeof(out[result].id));
      strlcpy(out[result].owner, devices[i].owner, sizeof(out[result].owner));
    }
  }

  taskENTER_CRITICAL(&mux);
  jobResult = result;
  jobState  = JOB_DONE;
  taskEXIT_CRITICAL(&mux);
}

void cloudLinkPhoneChanged(const char *phoneId, const char *owner, bool removed) {
  if (!phoneId || !phoneId[0]) return;
  PhoneChange c = {};
  strlcpy(c.phoneId, phoneId, sizeof(c.phoneId));
  strlcpy(c.owner, owner ? owner : "", sizeof(c.owner));
  c.removed = removed;

  bool enabled, queued = false;
  taskENTER_CRITICAL(&mux);
  enabled = fbSaved.enabled;
  if (enabled) {
    if (phOutboxCount < PH_OUTBOX) {
      phOutbox[phOutboxCount++] = c;
      queued = true;
    } else {
      phOutboxOverflow = true;   // adds come back with the next comparison
    }
  }
  taskEXIT_CRITICAL(&mux);
  if (enabled && !queued)
    Serial.printf("[PHONESYNC] Outbox full: %s of %s not sent to the web list%s\n", removed ? "removal" : "registration",
                  c.phoneId, removed ? "" : " (added at the next comparison)");
}
