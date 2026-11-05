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
#include "web_handler.h"   // FIRMWARE_VERSION, devices[], users[]
#include <ArduinoJson.h>   // shallow list replies, when comparing the lists

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
#ifdef CLOUD_PROJECT_ID
  char token[2048];
#else
  char token[1];   // no Firestore project in this build: never signed in, 2 KB more heap for TLS
#endif
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

// A change the web app's Overview shows live (motion, E-STOP, the BLE
// connection, SD/RTC, a pending restart) is pushed early instead of waiting
// for the next heartbeat, but at most once per FB_LIVE_GAP_MS: each push is a
// TLS session of its own, and the sync must still get its turns.
static const unsigned long FB_LIVE_GAP_MS = 5000;
static bool                fbLiveDirty    = false;   // under `mux`

static bool liveFieldsDiffer(const CloudStatus &a, const CloudStatus &b) {
  return a.estop != b.estop || a.up != b.up || a.down != b.down || a.left != b.left || a.right != b.right ||
         a.bleConn != b.bleConn || a.bleAuth != b.bleAuth || strcmp(a.bleUser, b.bleUser) != 0 || a.sdOk != b.sdOk ||
         a.rtcOk != b.rtcOk || a.netRestartPending != b.netRestartPending;
}

// ---- sync with the web app (see cloud_link.h) ----
// Every request is a TLS session of its own (~50 KB of heap, 1-3 s), so the
// flag is polled at a modest rate and the queues are read a few entries at a time.
static const unsigned long SY_POLL_MS      = 20000;   // tobesynced poll
static const unsigned long SY_RETRY_MS     = 30000;   // after a failed request
static const unsigned long SY_NEXT_MS      = 1000;    // between the jobs of one sync
static const unsigned long SY_LOOP_WAIT_MS = 30000;   // for loop() to pick up a job
static const int           SY_PAGES_PER_GO = 5;       // then let the heartbeat run
static const int           SY_LIST_BATCH   = 3;       // phonelist/userlist records per PATCH (fits mem->body)
static const int           SY_DELETE_BATCH = 8;       // stale list keys per PATCH
static const int           SY_OUTBOX       = 4;       // PLC-side changes waiting to be sent, per list
static const size_t        SY_STALE_CAP    = 2048;    // bytes of stale web keys handled per comparison
static const int           PH_PAGE         = 4;       // queue entries per GET (fits mem->resp)
static const int           US_PAGE         = 3;

// Changes made on the PLC, for phonelist / userlist, oldest first. Shared with
// loop(), under `mux`.
struct PhoneChange {
  char phoneId[PHONE_ID_MAX + 1];
  char owner[64];
  bool removed;
};
struct UserChange {
  char     email[64];
  char     name[64];
  char     role[16];
  uint8_t  accessType;
  uint32_t startTs, endTs;
  bool     removed;
};
static PhoneChange   phOutbox[SY_OUTBOX];
static int           phOutboxCount    = 0;
static bool          phOutboxOverflow = false;   // a change was dropped: compare the lists again
static UserChange    usOutbox[SY_OUTBOX];
static int           usOutboxCount    = 0;
static bool          usOutboxOverflow = false;

// Event upload (see cloudLinkLogEvent()): two rings, filled by loop() and
// emptied by the network task, under `mux`. Each entry has a running number;
// `*First` is the number of the oldest entry still in the ring, so the network
// task can tell what it has sent even if the ring overflowed meanwhile.
// The rings live in RTC slow memory, not in DRAM: every byte of DRAM is heap
// a TLS session needs (TLS_MIN_FREE_HEAP), and in DRAM these 5.4 KB kept the
// heap below it. RTC slow memory is reachable from both cores, is otherwise
// unused by this firmware, and is cleared at every boot like normal RAM.
static const int   EV_LOG_RING  = 20;   // ~3.9 KB
static const int   EV_ACC_RING  = 6;    // ~1.7 KB
static const int   EV_LOG_BATCH = 4;    // per PATCH (fits mem->body)
static const int   EV_ACC_BATCH = 2;
RTC_DATA_ATTR static CloudLogEntry    evLogs[EV_LOG_RING];
RTC_DATA_ATTR static CloudAccessEntry evAcc[EV_ACC_RING];
static int          evLogHead = 0, evLogCount = 0;
static int          evAccHead = 0, evAccCount = 0;
static uint32_t     evLogFirst = 0, evAccFirst = 0;
static uint32_t     evLogDropped = 0, evAccDropped = 0;   // lost to a full ring, not yet reported
static uint32_t     evUploaded = 0;
static uint32_t     evNoClock = 0;        // since boot: no valid clock time, not uploaded
static uint32_t     evDroppedTotal = 0;   // since boot: lost to a full ring
static char         evLogLastTs[20] = "", evAccLastTs[20] = "";
static unsigned     evLogSeq = 0, evAccSeq = 0;

static char          phState[96] = "Not started";
static char          usState[96] = "Not started";
static char          nwState[96] = "Not started";
static char          evState[96] = "Not started";
static bool          syEverOk    = false;
static unsigned long syLastOkMs  = 0;

// The network task's own sync state.
struct QueueRun {
  bool       pending;    // read the queue (once at boot, then when tobesynced)
  bool       active;     // a pass is under way: cursor and counts are live
  bool       stuck;      // cannot read past some entry: not retried until the next request
  bool       unsaved;    // the PLC could not store a change: retried after SY_RETRY_MS
  char       cursor[QUEUE_KEY_MAX + 1];
  SyncCounts counts;
  int        pageSize;
};
static QueueRun      phRun = {true};
static QueueRun      usRun = {true};
static bool          syReconcilePhones = true;   // compare the lists (once per boot)
static bool          syReconcileUsers  = true;
static bool          syNetPending      = true;   // look for queued network settings
static bool          syClearFlag       = false;  // tobesynced was true: set it false before reading
static unsigned long syNextPollMs      = 0;
static unsigned long syNextWorkMs      = 0;

// Work handed to loop()'s task, which owns devices[] and users[]. One job at a
// time: the network task sets it Requested; loop() takes it (Serving), does it
// and sets Done. The network task gives up only on a job loop() has not taken,
// so the buffer is never freed while loop() uses it.
enum : uint8_t { JOB_IDLE, JOB_REQUESTED, JOB_SERVING, JOB_DONE };
enum : uint8_t {
  JOB_APPLY_PHONES,     // buf = PhoneOp[count]
  JOB_APPLY_USERS,      // buf = UserOp[count]
  JOB_KEYS_PHONES,      // buf = NUL-separated keys, cap bytes; result = how many
  JOB_KEYS_USERS,
  JOB_RECORDS_PHONES,   // buf = PhoneOp[count] from index `start`; result = how many
  JOB_RECORDS_USERS,    // buf = UserOp[count]
  JOB_NETWORK,          // buf = NetworkRequest; result = stageCloudNetwork()
};
static volatile uint8_t jobState  = JOB_IDLE;
static uint8_t          jobKind   = JOB_APPLY_PHONES;
static void            *jobBuf    = nullptr;
static int              jobStart  = 0;
static int              jobCount  = 0;
static size_t           jobCap    = 0;
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

static void setUsState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(usState, sizeof(usState), "USERSYNC", fmt, ap);
  va_end(ap);
}

static void setNwState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(nwState, sizeof(nwState), "NETSYNC", fmt, ap);
  va_end(ap);
}

static void setEvState(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  setStateIn(evState, sizeof(evState), "EVENTS", fmt, ap);
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
  fbLiveDirty = false;   // this push carries the latest change
  memcpy(s.evState, evState, sizeof(s.evState));
  s.evQueued   = (uint32_t)(evLogCount + evAccCount);
  s.evUploaded = evUploaded;
  s.evNoClock  = evNoClock;
  s.evDropped  = evDroppedTotal;
  taskEXIT_CRITICAL(&mux);
  strlcpy(s.ip, Ethernet.localIP().toString().c_str(), sizeof(s.ip));
  s.uptimeS     = (uint32_t)(esp_timer_get_time() / 1000000LL);
  s.freeHeap    = (uint32_t)ESP.getFreeHeap();
  s.minFreeHeap = (uint32_t)ESP.getMinFreeHeap();

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

// ---------------- sync with the web app ----------------

typedef void (*StateFn)(const char *fmt, ...);

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

static PhRes syFailed(StateFn st, const char *what, int status, const char *stage) {
  if (status == 0) {
    st("%s failed at: %s", what, stage);
    return PhRes::Retry;
  }
  if (status == 401 || status == 403) {
    st("%s refused (HTTP %d): check the database secret", what, status);
    return PhRes::Rejected;
  }
  if (status == 404) {
    st("%s: database not found (HTTP 404)", what);
    return PhRes::Rejected;
  }
  st("%s refused (HTTP %d)", what, status);
  return status >= 500 ? PhRes::Retry : PhRes::Rejected;
}

static void syMarkOk() {
  taskENTER_CRITICAL(&mux);
  syEverOk   = true;
  syLastOkMs = millis();
  taskEXIT_CRITICAL(&mux);
}

// Runs a job on loop()'s task (see cloudLinkLoop()) and waits for it. False if
// loop() did not take it within SY_LOOP_WAIT_MS: it is then withdrawn, so
// `buf` is the caller's again either way.
static bool runOnLoop(uint8_t kind, void *buf, int start, int count, size_t cap, int &result) {
  taskENTER_CRITICAL(&mux);
  jobKind   = kind;
  jobBuf    = buf;
  jobStart  = start;
  jobCount  = count;
  jobCap    = cap;
  jobResult = 0;
  jobState  = JOB_REQUESTED;
  taskEXIT_CRITICAL(&mux);

  unsigned long t0 = millis();
  for (;;) {
    bool late = millis() - t0 >= SY_LOOP_WAIT_MS;
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

// Writes a synchistory record. A log, not state: a failed write is not retried.
static void writeHistory(const char *type, const char *status, const SyncCounts &c) {
  char ts[20];
  taskENTER_CRITICAL(&mux);
  memcpy(ts, sharedStatus.rtc, sizeof(ts));
  taskEXIT_CRITICAL(&mux);
  char key[24];
  cloudHistoryKey(ts, (unsigned long)(esp_timer_get_time() / 1000000LL), key, sizeof(key));
  char child[48];
  snprintf(child, sizeof(child), "synchistory/%s-%s", key, type);   // the type keeps same-second runs apart
  if (cloudBuildSyncRecord(mem->body, sizeof(mem->body), type, fb.deviceId, ts, status, c) == 0) return;
  if (!tlsHeapOk()) return;
  const char *stage = "";
  int st = fbRequest("PUT", child, "", mem->body, stage);
  if (st != 200) Serial.printf("[SYNC] History not written (HTTP %d %s)\n", st, st ? "" : stage);
}

// Sends one PATCH of a list (phonelist / userlist). PhRes::Ok also when the
// database refused it as invalid: dropped rather than retried forever.
static PhRes sendListPatch(StateFn st, const char *list, const char *what) {
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int status = fbRequest("PATCH", list, "", mem->body, stage);
  if (status == 200) {
    syMarkOk();
    return PhRes::Ok;
  }
  if (status == 400) {
    st("The web %s list refused a change (HTTP 400); dropped", what);
    return PhRes::Ok;
  }
  return syFailed(st, "Updating the web list", status, stage);
}

// ---- comparing the lists (after boot, or when a PLC change could not be queued) ----
// The PLC's entries are written to the web list (users: all of them; phones:
// the missing ones, so a model typed in the web app stays). Web entries the
// PLC does not have and that are not waiting in the queue are deleted: they
// were removed on the PLC while the sync was off, or cancelled in the web app.

struct ListSpec {
  const char *list;         // "phonelist"
  const char *queue;        // "tobesyncedphoneid"
  const char *what;         // "phone"
  uint8_t     keysJob, recordsJob;
  size_t      opSize;
  int         maxLocal;
  bool        upsertAll;
  size_t (*build)(char *out, size_t cap, const void *ops, int n);
  StateFn     state;
};

static bool keyInPool(const char *pool, int n, const char *key, int *index = nullptr) {
  const char *p = pool;
  for (int i = 0; i < n; i++, p += strlen(p) + 1) {
    if (strcmp(p, key) == 0) {
      if (index) *index = i;
      return true;
    }
  }
  return false;
}

static PhRes reconcileWith(const ListSpec &s, char *&local, char *&stale, void *&ops) {
  // A. The PLC's keys.
  size_t cap = (size_t)s.maxLocal * (QUEUE_KEY_MAX + 1);
  local = static_cast<char *>(malloc(cap));
  if (!local) return PhRes::Heap;
  int nLocal = 0;
  if (!runOnLoop(s.keysJob, local, 0, s.maxLocal, cap, nLocal)) {
    s.state("Waiting for the PLC main loop");
    return PhRes::Retry;
  }
  size_t used = 0;
  for (int i = 0; i < nLocal; i++) used += strlen(local + used) + 1;
  char *shrunk = static_cast<char *>(realloc(local, used ? used : 1));   // keep the heap free for TLS
  if (shrunk) local = shrunk;

  // B. The web list: which PLC entries it has, and which of its own the PLC does not.
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("GET", s.list, "shallow=true", "", stage);
  if (st != 200) return syFailed(s.state, "Reading the web list", st, stage);
  uint64_t present = 0;
  int nStale = 0;
  size_t staleUsed = 0;
  bool staleFull = false;
  {
    JsonDocument doc;
    if (deserializeJson(doc, cloudHttpBody(mem->resp) ? cloudHttpBody(mem->resp) : "")) {
      s.state("The web %s list is too long to compare; skipped", s.what);
      return PhRes::Ok;
    }
    if (doc.is<JsonObjectConst>()) {
      for (JsonPairConst kv : doc.as<JsonObjectConst>()) {
        const char *key = kv.key().c_str();
        int idx = -1;
        if (keyInPool(local, nLocal, key, &idx)) {
          if (idx < 64) present |= 1ULL << idx;
          continue;
        }
        size_t kl = strlen(key) + 1;
        if (!stale) stale = static_cast<char *>(malloc(SY_STALE_CAP));
        if (!stale || staleUsed + kl > SY_STALE_CAP) {
          staleFull = true;
          continue;
        }
        memcpy(stale + staleUsed, key, kl);
        staleUsed += kl;
        nStale++;
      }
    }
  }
  free(local);
  local = nullptr;
  syMarkOk();

  // C. Stale entries still waiting in the queue are not stale: keep them.
  if (nStale > 0) {
    if (!tlsHeapOk()) return PhRes::Heap;
    st = fbRequest("GET", s.queue, "shallow=true", "", stage);
    if (st != 200) return syFailed(s.state, "Reading the queue", st, stage);
    JsonDocument doc;
    if (deserializeJson(doc, cloudHttpBody(mem->resp) ? cloudHttpBody(mem->resp) : "")) {
      nStale = 0;   // cannot tell which are queued: delete nothing
    } else if (doc.is<JsonObjectConst>()) {
      JsonObjectConst queued = doc.as<JsonObjectConst>();
      char *w = stale;
      const char *r = stale;
      int kept = 0;
      for (int i = 0; i < nStale; i++) {
        size_t kl = strlen(r) + 1;
        if (queued[r].isNull()) {
          memmove(w, r, kl);
          w += kl;
          kept++;
        }
        r += kl;
      }
      nStale = kept;
    }
  }

  // D. Delete the stale ones.
  int deleted = 0;
  const char *p = stale;
  while (deleted < nStale) {
    const char *keys[SY_DELETE_BATCH];
    int k = 0;
    for (; k < SY_DELETE_BATCH && deleted + k < nStale; k++, p += strlen(p) + 1) keys[k] = p;
    if (cloudBuildDeleteKeys(mem->body, sizeof(mem->body), keys, k) == 0) break;
    PhRes r = sendListPatch(s.state, s.list, s.what);
    if (r != PhRes::Ok) return r;
    deleted += k;
  }
  free(stale);
  stale = nullptr;

  // E. Write the PLC's entries.
  ops = malloc(s.opSize * SY_LIST_BATCH);
  if (!ops) return PhRes::Heap;
  int written = 0;
  for (int start = 0;; start += SY_LIST_BATCH) {
    int got = 0;
    if (!runOnLoop(s.recordsJob, ops, start, SY_LIST_BATCH, 0, got)) {
      s.state("Waiting for the PLC main loop");
      return PhRes::Retry;
    }
    // Keep the ones to send, packed to the front.
    int k = 0;
    for (int i = 0; i < got; i++) {
      unsigned char *op = static_cast<unsigned char *>(ops) + s.opSize * i;
      const QueueOpHead &h = *reinterpret_cast<const QueueOpHead *>(op);
      int idx = start + i;
      bool have = idx < 64 && (present & (1ULL << idx));
      if (!h.key[0] || (!s.upsertAll && have)) continue;
      if (k != i) memmove(static_cast<unsigned char *>(ops) + s.opSize * k, op, s.opSize);
      k++;
    }
    if (k > 0) {
      if (s.build(mem->body, sizeof(mem->body), ops, k) == 0) {
        s.state("A %s record was too long to send; skipped", s.what);
      } else {
        PhRes r = sendListPatch(s.state, s.list, s.what);
        if (r != PhRes::Ok) return r;
        written += k;
      }
    }
    if (got < SY_LIST_BATCH) break;
  }
  if (staleFull) s.state("Compared; some old web %s entries are left for next time", s.what);
  else s.state("Compared: %d written to the web list, %d old ones removed", written, deleted);
  return PhRes::Ok;
}

static PhRes reconcile(const ListSpec &s) {
  char *local = nullptr, *stale = nullptr;
  void *ops = nullptr;
  PhRes r = reconcileWith(s, local, stale, ops);
  free(local);
  free(stale);
  if (ops) memset(ops, 0, s.opSize * SY_LIST_BATCH);
  free(ops);
  return r;
}

static size_t buildPhonelist(char *out, size_t cap, const void *ops, int n) {
  return cloudBuildPhonelistPatch(out, cap, static_cast<const PhoneOp *>(ops), n);
}
static size_t buildUserlist(char *out, size_t cap, const void *ops, int n) {
  return cloudBuildUserlistPatch(out, cap, static_cast<const UserOp *>(ops), n);
}

static const ListSpec PHONE_LIST = {"phonelist", "tobesyncedphoneid", "phone", JOB_KEYS_PHONES, JOB_RECORDS_PHONES,
                                    sizeof(PhoneOp), MAX_DEVICES, false, buildPhonelist, setPhState};
static const ListSpec USER_LIST  = {"userlist", "tobesyncedusers", "user", JOB_KEYS_USERS, JOB_RECORDS_USERS,
                                    sizeof(UserOp), MAX_USERS, true, buildUserlist, setUsState};

// ---- PLC-side changes ----

static PhRes flushPhoneOutbox() {
  PhoneChange batch[SY_LIST_BATCH];
  int k;
  taskENTER_CRITICAL(&mux);
  k = phOutboxCount < SY_LIST_BATCH ? phOutboxCount : SY_LIST_BATCH;
  memcpy(batch, phOutbox, sizeof(PhoneChange) * k);
  taskEXIT_CRITICAL(&mux);
  if (k == 0) return PhRes::Ok;

  PhoneOp *ops = static_cast<PhoneOp *>(malloc(sizeof(PhoneOp) * SY_LIST_BATCH));
  if (!ops) return PhRes::Heap;
  int used = 0, nOps = 0;   // outbox entries covered, ops built
  for (; used < k; used++) {
    PhoneOp &op = ops[nOps];
    memset(&op, 0, sizeof(op));
    if (!cloudPhoneKey(batch[used].phoneId, op.h.key, sizeof(op.h.key))) continue;   // no key: nothing to send
    bool again = false;   // the same phone twice: its later change goes in the next PATCH
    for (int j = 0; j < nOps; j++) again = again || strcmp(ops[j].h.key, op.h.key) == 0;
    if (again) break;
    strlcpy(op.phoneId, batch[used].phoneId, sizeof(op.phoneId));
    strlcpy(op.owner, batch[used].owner, sizeof(op.owner));
    op.h.action = batch[used].removed ? OP_REMOVE : OP_ADD;
    nOps++;
  }
  PhRes r = PhRes::Ok;
  if (nOps > 0) {
    if (cloudBuildPhonelistPatch(mem->body, sizeof(mem->body), ops, nOps) == 0) setPhState("A phone change was too long to send; dropped");
    else r = sendListPatch(setPhState, "phonelist", "phone");
  }
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

static PhRes flushUserOutbox() {
  UserChange batch[SY_LIST_BATCH];
  int k;
  taskENTER_CRITICAL(&mux);
  k = usOutboxCount < SY_LIST_BATCH ? usOutboxCount : SY_LIST_BATCH;
  memcpy(batch, usOutbox, sizeof(UserChange) * k);
  taskEXIT_CRITICAL(&mux);
  if (k == 0) return PhRes::Ok;

  UserOp *ops = static_cast<UserOp *>(malloc(sizeof(UserOp) * SY_LIST_BATCH));
  if (!ops) return PhRes::Heap;
  int used = 0, nOps = 0;
  for (; used < k; used++) {
    UserOp &op = ops[nOps];
    memset(&op, 0, sizeof(op));
    if (!cloudUserKey(batch[used].email, op.h.key, sizeof(op.h.key))) continue;
    bool again = false;
    for (int j = 0; j < nOps; j++) again = again || strcmp(ops[j].h.key, op.h.key) == 0;
    if (again) break;
    const UserChange &c = batch[used];
    op.h.action = c.removed ? OP_REMOVE : OP_ADD;
    strlcpy(op.email, c.email, sizeof(op.email));
    strlcpy(op.name, c.name, sizeof(op.name));
    strlcpy(op.role, c.role, sizeof(op.role));
    op.accessType = c.accessType;
    op.startTs    = c.startTs;
    op.endTs      = c.endTs;
    nOps++;
  }
  PhRes r = PhRes::Ok;
  if (nOps > 0) {
    if (cloudBuildUserlistPatch(mem->body, sizeof(mem->body), ops, nOps) == 0) setUsState("A user change was too long to send; dropped");
    else r = sendListPatch(setUsState, "userlist", "user");
  }
  free(ops);
  if (r != PhRes::Ok) return r;

  taskENTER_CRITICAL(&mux);
  memmove(usOutbox, usOutbox + used, sizeof(UserChange) * (usOutboxCount - used));
  usOutboxCount -= used;
  taskEXIT_CRITICAL(&mux);
  if (nOps > 0) setUsState("Sent %d user change(s) to the web list", nOps);
  return PhRes::Ok;
}

// ---- event upload ----

static bool eventsWaiting() {
  taskENTER_CRITICAL(&mux);
  bool w = evLogCount > 0 || evAccCount > 0;
  taskEXIT_CRITICAL(&mux);
  return w;
}

// Takes `n` entries off the front of a ring, but only those still there: if
// it overflowed meanwhile, the oldest ones were already dropped.
static void ringPop(int &head, int &count, uint32_t &first, int size, uint32_t sentFrom, int n) {
  uint32_t end = sentFrom + (uint32_t)n;   // one past the last entry sent
  while (count > 0 && first < end) {
    head = (head + 1) % size;
    count--;
    first++;
  }
}

// Uploads a few queued events in one root PATCH (bfa_logs + bfa_events).
static PhRes flushEvents() {
  CloudLogEntry    *logs = static_cast<CloudLogEntry *>(malloc(sizeof(CloudLogEntry) * EV_LOG_BATCH));
  CloudAccessEntry *acc  = static_cast<CloudAccessEntry *>(malloc(sizeof(CloudAccessEntry) * EV_ACC_BATCH));
  if (!logs || !acc) {
    free(logs);
    free(acc);
    return PhRes::Heap;
  }

  int nL, nA;
  uint32_t logFrom, accFrom, skipped;
  taskENTER_CRITICAL(&mux);
  nL = evLogCount < EV_LOG_BATCH ? evLogCount : EV_LOG_BATCH;
  nA = evAccCount < EV_ACC_BATCH ? evAccCount : EV_ACC_BATCH;
  for (int i = 0; i < nL; i++) logs[i] = evLogs[(evLogHead + i) % EV_LOG_RING];
  for (int i = 0; i < nA; i++) acc[i] = evAcc[(evAccHead + i) % EV_ACC_RING];
  logFrom = evLogFirst;
  accFrom = evAccFirst;
  skipped = evLogDropped + evAccDropped;
  taskEXIT_CRITICAL(&mux);

  if (nL > 0 && skipped) logs[0].skipped = skipped > 0xFFFF ? 0xFFFF : (uint16_t)skipped;
  size_t len;
  while ((len = cloudBuildEventsPatch(mem->body, sizeof(mem->body), fb.deviceId, logs, nL, acc, nA)) == 0 &&
         nL + nA > 1) {
    if (nL >= nA && nL > 0) nL--;   // send fewer: the rest go next time
    else nA--;
  }

  PhRes r = PhRes::Ok;
  int status = 0;
  const char *stage = "";
  if (len == 0) {
    status = 400;   // one entry alone does not fit (cannot happen with these sizes): drop it
  } else if (!tlsHeapOk()) {
    r = PhRes::Heap;
  } else {
    char path[96];   // holds the secret: keep it off the heap and out of every log
    if (cloudBuildRootPath(path, sizeof(path), fb.secret) == 0) {
      stage  = "building the request";
      status = 0;
    } else {
      status = httpsRequest("PATCH", fbHost, path, nullptr, mem->body, stage);
    }
    memset(path, 0, sizeof(path));
  }
  free(logs);
  free(acc);
  if (r != PhRes::Ok) return r;

  if (status == 200 || status == 400) {
    uint32_t total;
    taskENTER_CRITICAL(&mux);
    ringPop(evLogHead, evLogCount, evLogFirst, EV_LOG_RING, logFrom, nL);
    ringPop(evAccHead, evAccCount, evAccFirst, EV_ACC_RING, accFrom, nA);
    if (status == 200 && nL > 0 && skipped) {   // the gap is now on record
      uint32_t fromLogs = skipped < evLogDropped ? skipped : evLogDropped;
      evLogDropped -= fromLogs;
      uint32_t rest = skipped - fromLogs;
      evAccDropped -= rest < evAccDropped ? rest : evAccDropped;
    }
    if (status == 200) evUploaded += (uint32_t)(nL + nA);
    total = evUploaded;
    taskEXIT_CRITICAL(&mux);
    if (status == 200) {
      syMarkOk();
      setEvState("Uploaded %lu event(s) since boot", (unsigned long)total);
    } else {
      setEvState("The database refused %d event(s) (HTTP 400); dropped", nL + nA);
    }
    return PhRes::Ok;
  }
  return syFailed(setEvState, "Uploading events", status, stage);
}

// Next key for an event at `ts`: same second as the last one, next counter.
static bool nextEventKey(const char *ts, char *lastTs, unsigned &seq, char *key, size_t cap) {
  if (strcmp(ts, lastTs) == 0) {
    seq++;
  } else {
    seq = 0;
    strlcpy(lastTs, ts, 20);
  }
  return cloudEventKey(ts, seq, key, cap);
}

void cloudLinkLogEvent(const char *ts, const char *category, const char *detail) {
  if (!ts || !category) return;
  CloudLogEntry e = {};
  strlcpy(e.ts, ts, sizeof(e.ts));
  strlcpy(e.category, category, sizeof(e.category));
  strlcpy(e.detail, detail ? detail : "", sizeof(e.detail));
  taskENTER_CRITICAL(&mux);
  bool on = fbSaved.enabled && nextEventKey(e.ts, evLogLastTs, evLogSeq, e.key, sizeof(e.key));
  if (fbSaved.enabled && !on) evNoClock++;
  if (on) {
    if (evLogCount == EV_LOG_RING) {   // full: the oldest goes (it is on the SD card)
      evLogHead = (evLogHead + 1) % EV_LOG_RING;
      evLogCount--;
      evLogFirst++;
      evLogDropped++;
      evDroppedTotal++;
    }
    evLogs[(evLogHead + evLogCount) % EV_LOG_RING] = e;
    evLogCount++;
  }
  taskEXIT_CRITICAL(&mux);
}

void cloudLinkAccessEvent(const char *ts, bool authorized, const char *email, const char *name, const char *role,
                          const char *empId, const char *phoneId, const char *reason, unsigned suppressed) {
  if (!ts) return;
  CloudAccessEntry e = {};
  strlcpy(e.ts, ts, sizeof(e.ts));
  e.authorized = authorized;
  strlcpy(e.email, email ? email : "", sizeof(e.email));
  strlcpy(e.name, name ? name : "", sizeof(e.name));
  strlcpy(e.role, role ? role : "", sizeof(e.role));
  strlcpy(e.empId, empId ? empId : "", sizeof(e.empId));
  strlcpy(e.phoneId, phoneId ? phoneId : "", sizeof(e.phoneId));
  strlcpy(e.reason, reason ? reason : "", sizeof(e.reason));
  e.suppressed = suppressed > 0xFFFF ? 0xFFFF : (uint16_t)suppressed;
  taskENTER_CRITICAL(&mux);
  bool on = fbSaved.enabled && nextEventKey(e.ts, evAccLastTs, evAccSeq, e.key, sizeof(e.key));
  if (fbSaved.enabled && !on) evNoClock++;
  if (on) {
    if (evAccCount == EV_ACC_RING) {
      evAccHead = (evAccHead + 1) % EV_ACC_RING;
      evAccCount--;
      evAccFirst++;
      evAccDropped++;
      evDroppedTotal++;
    }
    evAcc[(evAccHead + evAccCount) % EV_ACC_RING] = e;
    evAccCount++;
  }
  taskEXIT_CRITICAL(&mux);
}

// ---- the queues ----

struct QueueSpec {
  const char *child;   // "tobesyncedphoneid"
  const char *type;    // synchistory type: "phones"
  size_t      opSize;
  int         page;
  uint8_t     applyJob;
  bool (*parse)(const char *body, const char *skip, void *ops, int maxOps, QueuePage &page);
  StateFn     state;
};

static bool parsePhones(const char *b, const char *s, void *ops, int m, QueuePage &p) {
  return cloudParsePhoneQueue(b, s, static_cast<PhoneOp *>(ops), m, p);
}
static bool parseUsers(const char *b, const char *s, void *ops, int m, QueuePage &p) {
  return cloudParseUserQueue(b, s, static_cast<UserOp *>(ops), m, p);
}

static const QueueSpec PHONE_QUEUE = {"tobesyncedphoneid", "phones", sizeof(PhoneOp), PH_PAGE, JOB_APPLY_PHONES,
                                      parsePhones, setPhState};
static const QueueSpec USER_QUEUE  = {"tobesyncedusers", "users", sizeof(UserOp), US_PAGE, JOB_APPLY_USERS,
                                      parseUsers, setUsState};

static void tally(SyncCounts &c, const QueueOpHead &h) {
  if (h.outcome == OP_PENDING) return;
  c.entries++;
  switch (h.outcome) {
    case OP_ADDED:    c.added++; break;
    case OP_UPDATED:  c.updated++; break;
    case OP_REMOVED:
    case OP_ABSENT:   c.removed++; break;
    case OP_REJECTED: c.rejected++; break;
    default: break;
  }
}

static const QueueOpHead &headAt(const void *ops, size_t stride, int i) {
  return *reinterpret_cast<const QueueOpHead *>(static_cast<const unsigned char *>(ops) + stride * i);
}

// One page of a queue: read it, apply it on loop(), confirm it. `done` once
// the end of the queue is reached.
static PhRes queuePage(const QueueSpec &q, QueueRun &run, void *ops, bool &done) {
  if (!tlsHeapOk()) return PhRes::Heap;

  // orderBy="$key" (no index needed). startAt includes the cursor, so one more
  // is asked for and the cursor itself is skipped.
  bool hasCursor = run.cursor[0] != '\0';
  int limit = hasCursor ? run.pageSize + 1 : run.pageSize;
  char query[200];   // with the rest of the path this stays inside fbRequest()'s 384 bytes
  int qn = snprintf(query, sizeof(query), "orderBy=%%22%%24key%%22&limitToFirst=%d", limit);
  if (hasCursor) {
    char quoted[QUEUE_KEY_MAX * 2 + 3];   // the cursor as a JSON string
    size_t n = 0;
    quoted[n++] = '"';
    for (const char *c = run.cursor; *c; c++) {
      if (*c == '"' || *c == '\\') quoted[n++] = '\\';
      quoted[n++] = *c;
    }
    quoted[n++] = '"';
    quoted[n] = '\0';
    char enc[sizeof(query)];
    if (cloudUrlEncode(quoted, enc, sizeof(enc)) == 0 ||
        snprintf(query + qn, sizeof(query) - qn, "&startAt=%s", enc) >= (int)(sizeof(query) - qn)) {
      q.state("A queue key is too long to read past");
      run.stuck = true;
      done = true;
      return PhRes::Ok;
    }
  }

  const char *stage = "";
  int st = fbRequest("GET", q.child, query, "", stage);
  if (st != 200) return syFailed(q.state, "Reading the sync queue", st, stage);

  QueuePage pg;
  if (!q.parse(cloudHttpBody(mem->resp), hasCursor ? run.cursor : nullptr, ops, q.page + 1, pg)) {
    if (run.pageSize > 1) {
      run.pageSize = 1;   // the page did not fit in the reply buffer: one entry at a time
      return PhRes::Ok;
    }
    q.state("A queue entry is too large to read");
    run.stuck = true;
    done = true;
    return PhRes::Ok;
  }
  if (pg.keyTooLong) q.state("Skipped a queue key longer than %d characters", QUEUE_KEY_MAX);

  if (pg.ops > 0) {
    int unused = 0;
    if (!runOnLoop(q.applyJob, ops, 0, pg.ops, 0, unused)) {
      q.state("Waiting for the PLC main loop");
      return PhRes::Retry;   // nothing was applied: the same page is read again
    }
    // Applied. If confirming fails the entries stay and the page is read again;
    // applying them twice changes nothing.
    int confirmable = 0;
    for (int i = 0; i < pg.ops; i++) confirmable += headAt(ops, q.opSize, i).outcome != OP_PENDING;
    int written = 0;
    size_t len = cloudBuildQueueResult(mem->body, sizeof(mem->body), ops, q.opSize, pg.ops, written);
    if (confirmable > 0 && len == 0) {
      q.state("Queue result too long to send");
      return PhRes::Retry;
    }
    if (written > 0) {
      if (!tlsHeapOk()) return PhRes::Heap;
      st = fbRequest("PATCH", q.child, "", mem->body, stage);
      if (st != 200) return syFailed(q.state, "Confirming queue entries", st, stage);
    }
    for (int i = 0; i < pg.ops; i++) tally(run.counts, headAt(ops, q.opSize, i));
    if (confirmable < pg.ops) run.unsaved = true;   // left pending: the PLC could not store them

    // Users the PLC now holds get their userlist record from the PLC itself
    // (source "plc"), so the web app shows them as on the PLC. Best effort:
    // the comparison after the next boot writes them anyway.
    if (q.applyJob == JOB_APPLY_USERS) {
      UserOp *u = static_cast<UserOp *>(ops);
      int k = 0;
      for (int i = 0; i < pg.ops; i++) {
        uint8_t o = u[i].h.outcome;
        if (o != OP_ADDED && o != OP_UPDATED && o != OP_UNCHANGED) continue;
        if (k != i) u[k] = u[i];
        u[k].h.action = OP_ADD;
        k++;
      }
      if (k > 0 && cloudBuildUserlistPatch(mem->body, sizeof(mem->body), u, k) > 0) sendListPatch(setUsState, "userlist", "user");
    }
  }
  syMarkOk();

  if (pg.keys < limit || !pg.haveLast) {
    done = true;
    return PhRes::Ok;
  }
  if (hasCursor && strcmp(pg.lastKey, run.cursor) == 0) {
    // A full page that ends at the cursor again: only unreadable keys after it.
    q.state("Cannot read past queue key %.40s", run.cursor);
    run.stuck = true;
    done = true;
    return PhRes::Ok;
  }
  strlcpy(run.cursor, pg.lastKey, sizeof(run.cursor));
  run.pageSize = q.page;
  return PhRes::Ok;
}

// Logs the pass in synchistory, if it did anything, and decides whether to
// run another: a pass that applied something is followed by one more, which
// picks up whatever the web app queued meanwhile (and anything paged past).
static PhRes finishPass(const QueueSpec &q, QueueRun &run) {
  run.active = false;
  const SyncCounts c = run.counts;
  bool applied = c.entries - c.rejected > 0;
  PhRes next = run.unsaved ? PhRes::Retry : PhRes::Ok;   // unsaved entries are still queued
  run.pending = run.unsaved || (applied && !run.stuck);

  if (run.unsaved) q.state("Could not save the change on the PLC; retrying");
  if (c.entries == 0) {
    if (!run.stuck && !run.unsaved) q.state("Up to date");
    return next;
  }
  const char *status = (run.stuck || run.unsaved) ? "incomplete" : (c.rejected > 0 ? "partial" : "success");
  if (!run.stuck && !run.unsaved)
    q.state("Synced: %d added, %d updated, %d removed, %d rejected", c.added, c.updated, c.removed, c.rejected);
  writeHistory(q.type, status, c);
  return next;
}

static PhRes queuePass(const QueueSpec &q, QueueRun &run) {
  if (!run.active) {
    run.active    = true;
    run.stuck     = false;
    run.unsaved   = false;
    run.cursor[0] = '\0';
    run.counts    = {};
    run.pageSize  = q.page;
    q.state("Reading the sync queue");
  }
  void *ops = malloc(q.opSize * (q.page + 1));
  if (!ops) return PhRes::Heap;
  PhRes r = PhRes::Ok;
  bool done = false;
  for (int pages = 0; pages < SY_PAGES_PER_GO && !done && r == PhRes::Ok; pages++) r = queuePage(q, run, ops, done);
  memset(ops, 0, q.opSize * (q.page + 1));   // user ops carry password hashes
  free(ops);
  if (r != PhRes::Ok || !done) return r;   // the rest next time, after any heartbeat
  return finishPass(q, run);
}

// ---- network settings ----

static PhRes networkCheck() {
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("GET", "tobesyncednetwork", "", "", stage);
  if (st != 200) return syFailed(setNwState, "Reading the network settings", st, stage);
  syMarkOk();

  NetworkRequest req;
  if (!cloudParseNetworkRequest(cloudHttpBody(mem->resp), req)) {
    setNwState("Queued network settings could not be read");
    return PhRes::Ok;
  }
  if (!req.present || req.rejected) {
    if (!req.present) setNwState(netRestartPending ? "Saved; restarts once no phone is connected" : "Up to date");
    return PhRes::Ok;
  }

  SyncCounts c = {};
  c.entries = 1;
  if (!req.valid) {
    char body[160];
    snprintf(body, sizeof(body), "{\"status\":\"rejected\",\"reason\":\"%s\"}", req.reason);   // reason: fixed text
    if (!tlsHeapOk()) return PhRes::Heap;
    st = fbRequest("PATCH", "tobesyncednetwork", "", body, stage);
    if (st != 200) return syFailed(setNwState, "Rejecting the network settings", st, stage);
    setNwState("Rejected: %s", req.reason);
    c.rejected = 1;
    writeHistory("network", "partial", c);
    return PhRes::Ok;
  }

  int staged = 0;
  bool ran = runOnLoop(JOB_NETWORK, &req, 0, 1, 0, staged);
  memset(req.wifiPassword, 0, sizeof(req.wifiPassword));
  if (!ran) {
    setNwState("Waiting for the PLC main loop");
    return PhRes::Retry;
  }
  if (staged < 0) {
    setNwState("Could not save the network settings on the PLC; retrying");
    return PhRes::Retry;
  }
  if (!tlsHeapOk()) return PhRes::Heap;
  st = fbRequest("DELETE", "tobesyncednetwork", "", "", stage);
  if (st != 200) return syFailed(setNwState, "Confirming the network settings", st, stage);
  if (staged == 0) {
    setNwState("Network settings already in use");
  } else {
    setNwState("Saved; restarts once no phone is connected");
    c.updated = 1;
    writeHistory("network", "success", c);
  }
  return PhRes::Ok;
}

static PhRes syncPoll() {
  if (!tlsHeapOk()) return PhRes::Heap;
  const char *stage = "";
  int st = fbRequest("GET", "tobesynced", "", "", stage);
  if (st != 200) return syFailed(setPhState, "Checking for a sync request", st, stage);
  syMarkOk();
  const char *body = cloudHttpBody(mem->resp);
  if (body && strncmp(body, "true", 4) == 0) {
    syClearFlag   = true;
    phRun.pending = true;
    usRun.pending = true;
    syNetPending  = true;
  }
  return PhRes::Ok;
}

static bool outboxWaiting(bool phones) {
  taskENTER_CRITICAL(&mux);
  bool w = phones ? phOutboxCount > 0 : usOutboxCount > 0;
  if (phones && phOutboxOverflow) {
    syReconcilePhones = true;
    phOutboxOverflow  = false;
  }
  if (!phones && usOutboxOverflow) {
    syReconcileUsers = true;
    usOutboxOverflow = false;
  }
  taskEXIT_CRITICAL(&mux);
  return w;
}

static bool syncDue(unsigned long now) {
  if ((long)(now - syNextWorkMs) < 0) return false;
  bool out = outboxWaiting(true) | outboxWaiting(false) | eventsWaiting();
  return syReconcilePhones || syReconcileUsers || out || syClearFlag || phRun.pending || usRun.pending || syNetPending ||
         (long)(now - syNextPollMs) >= 0;
}

// One job per call, so the heartbeat is never held up for long.
static void syncStep() {
  PhRes r;
  // Every other turn goes to the event upload first, so events are not held
  // up behind a list comparison or a queue that keeps failing.
  static bool eventsTurn = false;
  eventsTurn = !eventsTurn;
  if (eventsTurn && eventsWaiting()) {
    r = flushEvents();
  } else if (syReconcilePhones) {
    r = reconcile(PHONE_LIST);
    if (r == PhRes::Ok) syReconcilePhones = false;
  } else if (syReconcileUsers) {
    r = reconcile(USER_LIST);
    if (r == PhRes::Ok) syReconcileUsers = false;
  } else if (outboxWaiting(true)) {
    r = flushPhoneOutbox();
  } else if (outboxWaiting(false)) {
    r = flushUserOutbox();
  } else if (eventsWaiting()) {
    r = flushEvents();
  } else if (syClearFlag) {
    // Cleared before the queues are read: anything queued from now on sets it again.
    if (!tlsHeapOk()) {
      r = PhRes::Heap;
    } else {
      const char *stage = "";
      int st = fbRequest("PUT", "tobesynced", "", "false", stage);
      r = st == 200 ? PhRes::Ok : syFailed(setPhState, "Clearing tobesynced", st, stage);
      if (r == PhRes::Ok) syClearFlag = false;
    }
  } else if (phRun.pending) {
    r = queuePass(PHONE_QUEUE, phRun);
  } else if (usRun.pending) {
    r = queuePass(USER_QUEUE, usRun);
  } else if (syNetPending) {
    r = networkCheck();
    if (r == PhRes::Ok) syNetPending = false;
  } else {
    syNextPollMs = millis() + SY_POLL_MS;
    r = syncPoll();
  }

  unsigned long wait = SY_NEXT_MS;
  if (r == PhRes::Heap) wait = HEAP_RETRY_MS;
  else if (r == PhRes::Retry) wait = SY_RETRY_MS;
  else if (r == PhRes::Rejected) wait = RETRY_MAX_MS;
  syNextWorkMs = millis() + wait;
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
  static unsigned long fbLastTryMs  = 0;

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
    // New settings (or boot): compare the lists and read the queues afresh.
    syReconcilePhones = true;
    syReconcileUsers  = true;
    syNetPending      = true;
    syClearFlag       = false;
    phRun.pending     = true;
    phRun.active      = false;
    usRun.pending     = true;
    usRun.active      = false;
    syNextPollMs      = now;
    syNextWorkMs      = now;
  }

  // Firestore needs a project in the build; the Realtime Database push does not.
  bool fsOn = PROJECT_ID && creds.plcId[0];
  bool fbOn = fbActive();
  if (!fsOn) setState("%s", creds.plcId[0] ? "No cloud project set in this build" : "Not configured");
  if (!fbOn) {
    setFbState("%s", fb.enabled ? "Settings incomplete" : (fb.deviceId[0] ? "Disabled" : "Not configured"));
    setPhState("Off: Firebase push is not enabled");
    setUsState("Off: Firebase push is not enabled");
    setNwState("Off: Firebase push is not enabled");
    setEvState("Off: Firebase push is not enabled");
  }
  if (!fsOn && !fbOn) return;

  // Network trouble is shown on every service that is waiting for the network.
  auto netState = [&](const char *msg) {
    if (fsOn) setState("%s", msg);
    if (fbOn) {
      setFbState("%s", msg);
      setPhState("%s", msg);
      setUsState("%s", msg);
      setNwState("%s", msg);
      setEvState("%s", msg);
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
  if (fbOn && !fbDue && fbFailStreak == 0 && now - fbLastTryMs >= FB_LIVE_GAP_MS) {
    taskENTER_CRITICAL(&mux);
    fbDue = fbLiveDirty;   // pushed early; the next heartbeat is counted from this push
    taskEXIT_CRITICAL(&mux);
  }
  // The sync only fills the gaps: never in the same step as a heartbeat.
  bool phDue = fbOn && !fsDue && !fbDue && syncDue(now);
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
      syNextWorkMs = now + HEAP_RETRY_MS;
    }
    return;
  }

  if (phDue) {
    syncStep();
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
    fbLastTryMs = millis();
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
  if (liveFieldsDiffer(sharedStatus, status)) fbLiveDirty = true;
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
  strlcpy(info.userState, usState, sizeof(info.userState));
  strlcpy(info.networkState, nwState, sizeof(info.networkState));
  strlcpy(info.eventState, evState, sizeof(info.eventState));
  info.phoneEverOk     = syEverOk;
  info.phoneLastOkAgoS = syEverOk ? (millis() - syLastOkMs) / 1000UL : 0;
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


// ---------------- sync with the web app: loop() side ----------------

static void phoneRecord(PhoneOp &op, const Device &d) {
  memset(&op, 0, sizeof(op));
  if (!cloudPhoneKey(d.id, op.h.key, sizeof(op.h.key))) op.h.key[0] = '\0';   // skipped by the sender
  strlcpy(op.phoneId, d.id, sizeof(op.phoneId));
  strlcpy(op.owner, d.owner, sizeof(op.owner));
  op.h.action = OP_ADD;
}

static void userRecord(UserOp &op, const User &u) {
  memset(&op, 0, sizeof(op));
  if (!cloudUserKey(u.email, op.h.key, sizeof(op.h.key))) op.h.key[0] = '\0';
  strlcpy(op.email, u.email, sizeof(op.email));
  strlcpy(op.name, u.name, sizeof(op.name));
  strlcpy(op.role, u.role, sizeof(op.role));
  op.accessType = u.accessType == ACCESS_TIMED ? 1 : 0;
  op.startTs    = u.startTs;
  op.endTs      = u.endTs;
  op.h.action   = OP_ADD;   // never the password
}

// Appends the RTDB keys of `n` entries to `pool` (NUL-separated, `cap` bytes).
// Key i belongs to entry i: one without a key gets "" (matches no web key), so
// the indices stay those of JOB_RECORDS_*.
template <class KeyOf>
static int collectKeys(char *pool, size_t cap, int n, int max, KeyOf keyOf) {
  size_t used = 0;
  int count = 0;
  for (int i = 0; i < n && count < max; i++) {
    char key[QUEUE_KEY_MAX + 1];
    if (!keyOf(i, key, sizeof(key))) key[0] = '\0';
    size_t kl = strlen(key) + 1;
    if (used + kl > cap) break;
    memcpy(pool + used, key, kl);
    used += kl;
    count++;
  }
  return count;
}

void cloudLinkLoop() {
  if (jobState != JOB_REQUESTED) return;   // the usual case: one volatile read

  taskENTER_CRITICAL(&mux);
  bool mine = jobState == JOB_REQUESTED;
  if (mine) jobState = JOB_SERVING;   // from here on the network task waits for us
  uint8_t kind  = jobKind;
  void   *buf   = jobBuf;
  int     start = jobStart;
  int     count = jobCount;
  size_t  cap   = jobCap;
  taskEXIT_CRITICAL(&mux);
  if (!mine) return;

  int result = 0;
  switch (kind) {
    case JOB_APPLY_PHONES:
      applyCloudPhoneOps(static_cast<PhoneOp *>(buf), count);
      result = count;
      break;
    case JOB_APPLY_USERS:
      applyCloudUserOps(static_cast<UserOp *>(buf), count);
      result = count;
      break;
    case JOB_KEYS_PHONES:
      result = collectKeys(static_cast<char *>(buf), cap, deviceCount, count,
                           [](int i, char *k, size_t c) { return cloudPhoneKey(devices[i].id, k, c); });
      break;
    case JOB_KEYS_USERS:
      result = collectKeys(static_cast<char *>(buf), cap, userCount, count,
                           [](int i, char *k, size_t c) { return cloudUserKey(users[i].email, k, c); });
      break;
    case JOB_RECORDS_PHONES:
      for (int i = start; i < deviceCount && result < count; i++) phoneRecord(static_cast<PhoneOp *>(buf)[result++], devices[i]);
      break;
    case JOB_RECORDS_USERS:
      for (int i = start; i < userCount && result < count; i++) userRecord(static_cast<UserOp *>(buf)[result++], users[i]);
      break;
    case JOB_NETWORK: {
      const NetworkRequest *r = static_cast<const NetworkRequest *>(buf);
      result = stageCloudNetwork(r->bleName, r->ssid, r->wifiPassword);
      break;
    }
    default:
      break;
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
    if (phOutboxCount < SY_OUTBOX) {
      phOutbox[phOutboxCount++] = c;
      queued = true;
    } else {
      phOutboxOverflow = true;   // the lists are compared again instead
    }
  }
  taskEXIT_CRITICAL(&mux);
  if (enabled && !queued) Serial.printf("[PHONESYNC] Outbox full: the lists will be compared again\n");
}

static void queueUserChange(const UserChange &c) {
  bool enabled, queued = false;
  taskENTER_CRITICAL(&mux);
  enabled = fbSaved.enabled;
  if (enabled) {
    if (usOutboxCount < SY_OUTBOX) {
      usOutbox[usOutboxCount++] = c;
      queued = true;
    } else {
      usOutboxOverflow = true;   // the lists are compared again instead
    }
  }
  taskEXIT_CRITICAL(&mux);
  if (enabled && !queued) Serial.printf("[USERSYNC] Outbox full: the lists will be compared again\n");
}

void cloudLinkUserChanged(const User *now, const char *removedEmail) {
  if (removedEmail && removedEmail[0]) {
    UserChange c = {};
    strlcpy(c.email, removedEmail, sizeof(c.email));
    c.removed = true;
    queueUserChange(c);
  }
  if (now && now->email[0]) {
    UserChange c = {};
    strlcpy(c.email, now->email, sizeof(c.email));
    strlcpy(c.name, now->name, sizeof(c.name));
    strlcpy(c.role, now->role, sizeof(c.role));
    c.accessType = now->accessType == ACCESS_TIMED ? 1 : 0;
    c.startTs    = now->startTs;
    c.endTs      = now->endTs;
    queueUserChange(c);
  }
}
