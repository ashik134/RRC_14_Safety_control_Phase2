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

#ifndef CLOUD_PROJECT_ID
#define CLOUD_PROJECT_ID "web-app-intelliguard"
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

static void setState(const char *fmt, ...) {
  char msg[sizeof(sharedState)];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  taskENTER_CRITICAL(&mux);
  bool changed = strcmp(msg, sharedState) != 0;
  if (changed) memcpy(sharedState, msg, sizeof(sharedState));
  taskEXIT_CRITICAL(&mux);
  if (changed) Serial.printf("[CLOUD] %s\n", msg);
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

// One complete HTTPS POST. HTTP/1.0 keeps the reply simple: no chunked encoding,
// and the server closes the connection at the end. The whole reply lands in
// mem->resp, NUL-terminated. Returns the HTTP status, or 0 with `stage` naming
// the step that failed. The certificate is always verified, so the device key
// and token only ever go to Google.
static int httpsPost(const char *host, const char *path, const char *bearer, const char *body, const char *&stage) {
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
    char head[320];
    size_t bodyLen = strlen(body);
    int n = snprintf(head, sizeof(head),
                     "POST %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: plc14\r\nContent-Type: application/json\r\n"
                     "Content-Length: %u\r\nConnection: close\r\n",
                     path, host, (unsigned)bodyLen);
    bool sent = n > 0 && (size_t)n < sizeof(head) && sslWriteAll(&ssl, head, (size_t)n);
    if (sent && bearer) {
      sent = sslWriteAll(&ssl, "Authorization: Bearer ", 22) && sslWriteAll(&ssl, bearer, strlen(bearer)) &&
             sslWriteAll(&ssl, "\r\n", 2);
    }
    if (sent) sent = sslWriteAll(&ssl, "\r\n", 2) && sslWriteAll(&ssl, body, bodyLen);

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
  int status = httpsPost(AUTH_HOST, path, nullptr, mem->body, stage);
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

  if (cloudBuildHeartbeat(mem->body, sizeof(mem->body), CLOUD_PROJECT_ID, creds.plcId, FIRMWARE_VERSION, s) == 0) {
    setState("Heartbeat too long to send");
    return false;
  }

  const char *stage = "";
  int status = httpsPost(FIRESTORE_HOST, "/v1/projects/" CLOUD_PROJECT_ID "/databases/(default)/documents:commit",
                         mem->token, mem->body, stage);
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

static void cloudStep() {
  static bool          netUp       = false;
  static unsigned long nextDhcpMs  = 0;
  static unsigned long nextBeatMs  = 0;
  static unsigned long tokenAtMs   = 0;
  static uint32_t      failStreak  = 0;

  unsigned long now = millis();

  taskENTER_CRITICAL(&mux);
  bool changed = credsChanged;
  if (changed) {
    creds = savedCreds;
    credsChanged = false;
  }
  taskEXIT_CRITICAL(&mux);
  if (changed) {
    if (mem) mem->token[0] = '\0';
    failStreak = 0;
    nextBeatMs = now;
  }

  if (!creds.plcId[0]) {
    setState("Not configured");
    return;
  }

  EthDiagStatus eth = ethDiagGetStatus();
  if (!eth.chipDetected) {
    setState("No Ethernet hardware detected");
    return;
  }
  if (!eth.linkUp) {
    netUp = false;
    setState("Ethernet cable not connected");
    return;
  }

  if (!netUp) {
    if ((long)(now - nextDhcpMs) < 0) return;
    setState("Requesting an address (DHCP)");
    netUp = ethDiagStartDhcp();
    if (!netUp) {
      nextDhcpMs = millis() + DHCP_RETRY_MS;
      setState("No DHCP server on this network");
      return;
    }
    now = millis();
  }

  if ((long)(now - nextBeatMs) < 0) return;

  int lease = Ethernet.maintain();
  if (lease == DHCP_CHECK_RENEW_FAIL || lease == DHCP_CHECK_REBIND_FAIL) {
    netUp = false;
    return;
  }

  if (ESP.getFreeHeap() < TLS_MIN_FREE_HEAP || ESP.getMaxAllocHeap() < TLS_MIN_LARGEST || !prepareTls()) {
    // In whole KB: a figure that moves every retry would reprint this line each time.
    setState("Waiting for free memory (%u KB free, %u KB largest)", (unsigned)(ESP.getFreeHeap() / 1024), (unsigned)(ESP.getMaxAllocHeap() / 1024));
    nextBeatMs = now + HEAP_RETRY_MS;
    return;
  }

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
    return;
  }

  taskENTER_CRITICAL(&mux);
  failCount++;
  taskEXIT_CRITICAL(&mux);
  unsigned long wait = outcome == Outcome::Rejected ? RETRY_MAX_MS : RETRY_MIN_MS << (failStreak < 5 ? failStreak : 5);
  if (wait > RETRY_MAX_MS) wait = RETRY_MAX_MS;
  failStreak++;
  nextBeatMs = millis() + wait;
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

static volatile bool taskRunning = false;

// Started only once a login exists: the stack is 12 KB of a heap that can be
// as low as ~45 KB, which an unconfigured PLC should not have to give up.
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
  }
}

bool cloudLinkRunning() { return taskRunning; }

void cloudLinkBegin() {
  loadCreds();
  if (savedCreds.plcId[0]) startTask();
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
  startTask();
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
