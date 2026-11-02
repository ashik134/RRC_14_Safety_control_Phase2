// TLS-over-W5500 feasibility test. NOT crane firmware: build it only with
// `pio run -e tls_spike`, and run it on the bench. It has no safety logic and
// never drives the PLC outputs.
//
// It answers whether HTTPS to Firebase can work on this PLC, and what it costs:
//   - DHCP, DNS and internet reachability on the site network
//   - certificate validation, including two tests that MUST be rejected
//   - peak heap, largest free block, stack use, handshake time
//   - whether a low-priority network task disturbs a loop() that shares the
//     SPI bus with it (the same bus the SD card and W5500 share in production)
//
// BLE and the Wi-Fi AP are started so the heap looks like the real firmware.
// No credentials are sent; requests are anonymous, so Firebase answers 403/404,
// and any such HTTP reply proves the whole path works. Nothing is written.
//
// The file compiles to nothing in env:board.
#ifdef TLS_SPIKE

#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <WiFi.h>
#include <Ethernet.h>
#include <Dns.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <esp_bt.h>
#include <esp_system.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>

#include "roots_pem.h"

// Same wiring as eth_diag.cpp.
static const int SD_CS_PIN = 5;
static const int ETH_RESET_PIN = 4;
#ifdef PIN_SPI_SS_ETHERNET_LIB
static const uint8_t ETH_CS_PIN = PIN_SPI_SS_ETHERNET_LIB;
#else
static const uint8_t ETH_CS_PIN = 14;
#endif

#ifndef SPIKE_CYCLE_MS
#define SPIKE_CYCLE_MS 15000
#endif

// Time limits. A session can never outlast SESSION_BUDGET_MS plus one read.
static const uint16_t      DNS_TIMEOUT_MS    = 3000;
static const uint16_t      TCP_TIMEOUT_MS    = 4000;
static const uint32_t      TLS_READ_MS       = 5000;
static const unsigned long SESSION_BUDGET_MS = 20000;

struct Target {
  const char *host;
  const char *path;
};

static const Target TARGETS[] = {
  {"firestore.googleapis.com", "/v1/projects/web-app-intelliguard/databases/(default)/documents/plcs/tls-spike"},
  {"identitytoolkit.googleapis.com", "/"},
  {"securetoken.googleapis.com", "/"},
};
static const size_t TARGET_COUNT = sizeof(TARGETS) / sizeof(TARGETS[0]);

static mbedtls_x509_crt rightCa;
static mbedtls_x509_crt wrongCa;

// Read by the network task, written by loop().
static volatile unsigned long loopMaxGapMs = 0;
static volatile uint32_t      sdReads      = 0;
static volatile uint32_t      sdFails      = 0;
static bool                   sdPresent    = false;
static uint32_t               heapBaseline = 0;

// ---------------- mbedTLS transport over EthernetClient ----------------

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

// The hardware RNG; true random while Wi-Fi/BT are running, which they are.
static int rng(void *, unsigned char *out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

struct Result {
  const char *stage    = "start";
  int         tlsErr   = 0;
  uint32_t    verify   = 0;
  uint32_t    dnsMs    = 0;
  uint32_t    tcpMs    = 0;
  uint32_t    tlsMs    = 0;
  uint32_t    httpMs   = 0;
  const char *cipher   = "";
  char        status[40] = "";
};

// One complete HTTPS GET. Returns true only if the handshake verified and an
// HTTP status line came back. `verifyName` is normally `host`: passing another
// name is the hostname-mismatch test.
static bool httpsGet(const char *host, const char *verifyName, mbedtls_x509_crt *ca, const char *path, Result &r) {
  unsigned long t0 = millis();
  bool ok = false;

  IPAddress ip;
  DNSClient dns;
  dns.begin(Ethernet.dnsServerIP());
  if (dns.getHostByName(host, ip, DNS_TIMEOUT_MS) != 1) {
    r.stage = "dns";
    return false;
  }
  r.dnsMs = millis() - t0;

  EthernetClient tcp;
  tcp.setConnectionTimeout(TCP_TIMEOUT_MS);
  t0 = millis();
  if (!tcp.connect(ip, 443)) {
    r.stage = "tcp";
    tcp.stop();
    return false;
  }
  r.tcpMs = millis() - t0;

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config  conf;
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  Bio bio = {&tcp, millis()};

  t0 = millis();
  r.stage = "tls_setup";
  r.tlsErr = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (r.tlsErr == 0) {
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, ca, nullptr);
    mbedtls_ssl_conf_rng(&conf, rng, nullptr);
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);  // TLS 1.2+
    mbedtls_ssl_conf_read_timeout(&conf, TLS_READ_MS);
    r.tlsErr = mbedtls_ssl_setup(&ssl, &conf);   // allocates the record buffers
  }
  if (r.tlsErr == 0) r.tlsErr = mbedtls_ssl_set_hostname(&ssl, verifyName);

  if (r.tlsErr == 0) {
    mbedtls_ssl_set_bio(&ssl, &bio, bioSend, nullptr, bioRecv);
    r.stage = "tls_handshake";
    do {
      r.tlsErr = mbedtls_ssl_handshake(&ssl);
    } while (r.tlsErr == MBEDTLS_ERR_SSL_WANT_READ || r.tlsErr == MBEDTLS_ERR_SSL_WANT_WRITE);
    r.verify = mbedtls_ssl_get_verify_result(&ssl);
  }
  r.tlsMs = millis() - t0;

  if (r.tlsErr == 0) {
    r.cipher = mbedtls_ssl_get_ciphersuite(&ssl);
    t0 = millis();
    r.stage = "http";

    char req[220];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: plc14-tls-spike\r\nConnection: close\r\n\r\n", path, host);
    int off = 0;
    while (off < n) {
      int w = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char *>(req) + off, n - off);
      if (w <= 0) {
        r.tlsErr = w;
        break;
      }
      off += w;
    }

    // The first read holds the status line; the rest is drained so the
    // connection closes cleanly. Bounded by the session budget.
    size_t got = 0;
    unsigned char chunk[256];
    while (off == n && millis() - bio.startMs < SESSION_BUDGET_MS) {
      int rd = mbedtls_ssl_read(&ssl, chunk, sizeof(chunk));
      if (rd <= 0) break;
      for (int i = 0; i < rd && got < sizeof(r.status) - 1; i++) {
        if (chunk[i] == '\r' || chunk[i] == '\n') {
          got = sizeof(r.status);   // status line complete
          break;
        }
        r.status[got++] = (char)chunk[i];
      }
    }
    r.httpMs = millis() - t0;
    ok = strncmp(r.status, "HTTP/1.", 7) == 0;
    if (ok) r.stage = "done";
    mbedtls_ssl_close_notify(&ssl);
  }

  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  tcp.stop();
  return ok;
}

// ---------------- reporting ----------------

static void printHeap(const char *label) {
  Serial.printf("[SPIKE] heap %-12s free=%u largest=%u min_ever=%u\n", label, (unsigned)ESP.getFreeHeap(),
                (unsigned)ESP.getMaxAllocHeap(), (unsigned)ESP.getMinFreeHeap());
}

static void printResult(const char *label, bool ok, const Result &r) {
  Serial.printf("[SPIKE] %s %s stage=%s dns=%lums tcp=%lums tls=%lums http=%lums status='%s' cipher=%s err=-0x%04X verify=0x%08lX\n",
                label, ok ? "OK" : "FAIL", r.stage, (unsigned long)r.dnsMs, (unsigned long)r.tcpMs, (unsigned long)r.tlsMs,
                (unsigned long)r.httpMs, r.status, r.cipher, (unsigned)(-r.tlsErr), (unsigned long)r.verify);
}

// A forged or misdirected server must be refused. The handshake failing with a
// non-zero verify result is the only pass.
static bool expectRejected(const char *label, const char *verifyName, mbedtls_x509_crt *ca) {
  Result r;
  bool accepted = httpsGet(TARGETS[0].host, verifyName, ca, "/", r);
  bool reached  = strcmp(r.stage, "tls_handshake") == 0;
  bool pass     = !accepted && reached && r.verify != 0;
  Serial.printf("[SPIKE] NEGATIVE %-16s %s (stage=%s err=-0x%04X verify=0x%08lX)\n", label,
                pass ? "PASS - rejected" : accepted ? "FAIL - ACCEPTED A BAD CERTIFICATE" : "INCONCLUSIVE - did not reach verification",
                r.stage, (unsigned)(-r.tlsErr), (unsigned long)r.verify);
  return pass;
}

static void networkTask(void *) {
  uint32_t cycle = 0, okCount = 0, failCount = 0;
  uint32_t tlsMin = UINT32_MAX, tlsMax = 0, tlsSum = 0;

  bool negHost = expectRejected("wrong-hostname", "wrong.example.com", &rightCa);
  bool negRoot = expectRejected("wrong-root-ca", TARGETS[0].host, &wrongCa);

  for (;;) {
    Ethernet.maintain();
    for (size_t i = 0; i < TARGET_COUNT; i++) {
      Result r;
      bool ok = httpsGet(TARGETS[i].host, TARGETS[i].host, &rightCa, TARGETS[i].path, r);
      printResult(TARGETS[i].host, ok, r);
      if (ok) {
        okCount++;
        tlsSum += r.tlsMs;
        if (r.tlsMs < tlsMin) tlsMin = r.tlsMs;
        if (r.tlsMs > tlsMax) tlsMax = r.tlsMs;
      } else {
        failCount++;
      }
      vTaskDelay(pdMS_TO_TICKS(200));
    }
    cycle++;
    Serial.printf("[SPIKE] SUMMARY cycle=%lu ok=%lu fail=%lu neg_host=%s neg_root=%s tls_ms=%lu/%lu/%lu "
                  "heap_base=%lu heap_now=%u heap_min=%u largest=%u peak_cost=%ld stack_free=%u "
                  "loop_max_gap=%lums sd_reads=%lu sd_fails=%lu link=%s\n",
                  (unsigned long)cycle, (unsigned long)okCount, (unsigned long)failCount,
                  negHost ? "PASS" : "FAIL", negRoot ? "PASS" : "FAIL",
                  (unsigned long)(okCount ? tlsMin : 0), (unsigned long)(okCount ? tlsSum / okCount : 0), (unsigned long)tlsMax,
                  (unsigned long)heapBaseline, (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
                  (unsigned)ESP.getMaxAllocHeap(), (long)heapBaseline - (long)ESP.getMinFreeHeap(),
                  (unsigned)uxTaskGetStackHighWaterMark(nullptr), (unsigned long)loopMaxGapMs,
                  (unsigned long)sdReads, (unsigned long)sdFails,
                  Ethernet.linkStatus() == LinkON ? "UP" : "DOWN");
    vTaskDelay(pdMS_TO_TICKS(SPIKE_CYCLE_MS));
  }
}

// ---------------- bring-up ----------------

static bool startEthernet() {
  pinMode(ETH_CS_PIN, OUTPUT);
  digitalWrite(ETH_CS_PIN, HIGH);
  SPI.begin();
  pinMode(ETH_RESET_PIN, OUTPUT);
  digitalWrite(ETH_RESET_PIN, LOW);
  delay(20);
  digitalWrite(ETH_RESET_PIN, HIGH);
  delay(150);

  uint64_t efuse = ESP.getEfuseMac();
  uint8_t mac[6] = {0x02, (uint8_t)(efuse >> 0), (uint8_t)(efuse >> 8),
                    (uint8_t)(efuse >> 16), (uint8_t)(efuse >> 24), (uint8_t)(efuse >> 32)};
  Ethernet.init(ETH_CS_PIN);
  unsigned long t0 = millis();
  if (Ethernet.begin(mac, 8000, 2000) != 1) {
    Serial.printf("[SPIKE] DHCP FAILED after %lums (hardware: %s, link: %s)\n", millis() - t0,
                  Ethernet.hardwareStatus() == EthernetW5500 ? "W5500" : "NOT FOUND",
                  Ethernet.linkStatus() == LinkON ? "UP" : "DOWN");
    return false;
  }
  Ethernet.setRetransmissionTimeout(200);   // W5500 defaults: suits a WAN path
  Ethernet.setRetransmissionCount(8);
  Serial.printf("[SPIKE] DHCP OK in %lums ip=%s gateway=%s dns=%s\n", millis() - t0,
                Ethernet.localIP().toString().c_str(), Ethernet.gatewayIP().toString().c_str(),
                Ethernet.dnsServerIP().toString().c_str());
  return true;
}

// Reproduces the radios the real firmware runs, in the same order.
static void startRadios() {
  char pass[16];
  snprintf(pass, sizeof(pass), "%012llx", ESP.getEfuseMac());   // nothing joins this AP
  WiFi.mode(WIFI_AP);
  WiFi.softAP("TLS_SPIKE", pass, 1, 1);

  esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
  BLEDevice::init("TLS_SPIKE");
  BLEServer *server = BLEDevice::createServer();
  BLEService *service = server->createService(BLEUUID((uint16_t)0x180F));
  service->createCharacteristic(BLEUUID((uint16_t)0x2A19), BLECharacteristic::PROPERTY_READ);
  service->start();
  BLEDevice::getAdvertising()->start();
}

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("[SPIKE] TLS over W5500 test - bench use only, this is not crane firmware");
  esp_log_level_set("wifi", ESP_LOG_NONE);   // see the note in main.cpp setup()
  Serial.printf("[SPIKE] flash=%uMB (chip reports) psram=%u\n", (unsigned)(ESP.getFlashChipSize() / (1024 * 1024)), (unsigned)ESP.getPsramSize());
  printHeap("boot");

  sdPresent = SD.begin(SD_CS_PIN);
  Serial.printf("[SPIKE] SD %s\n", sdPresent ? "present (raw reads only, nothing is written)" : "not found, shared-bus test skipped");

  if (!startEthernet()) {
    Serial.println("[SPIKE] STOP: no network. Check cable, switch and DHCP, then reset.");
    return;
  }

  startRadios();
  printHeap("radios up");

  mbedtls_x509_crt_init(&rightCa);
  mbedtls_x509_crt_init(&wrongCa);
  int e1 = mbedtls_x509_crt_parse(&rightCa, reinterpret_cast<const unsigned char *>(GTS_ROOTS_PEM), sizeof(GTS_ROOTS_PEM));
  int e2 = mbedtls_x509_crt_parse(&wrongCa, reinterpret_cast<const unsigned char *>(WRONG_ROOT_PEM), sizeof(WRONG_ROOT_PEM));
  if (e1 != 0 || e2 != 0) {
    Serial.printf("[SPIKE] STOP: root certificate parse failed (-0x%04X, -0x%04X)\n", (unsigned)(-e1), (unsigned)(-e2));
    return;
  }

  heapBaseline = ESP.getFreeHeap();
  printHeap("baseline");

  // Core 0, lowest application priority: the BLE and Wi-Fi stacks preempt it
  // and loop() on core 1 is never blocked by it, the layout production would use.
  xTaskCreatePinnedToCore(networkTask, "tls_spike", 12288, nullptr, 1, nullptr, 0);
}

// Stands in for the safety loop: keeps the real 20 ms cadence and touches the
// shared SPI bus, then records the longest gap between iterations.
void loop() {
  static unsigned long last = 0;
  static unsigned long lastSd = 0;
  unsigned long now = millis();
  if (last != 0 && now - last > loopMaxGapMs) loopMaxGapMs = now - last;
  last = now;

  if (sdPresent && now - lastSd >= 200) {
    lastSd = now;
    static uint8_t sector[512];
    sdReads = sdReads + 1;
    if (!SD.readRAW(sector, 0)) sdFails = sdFails + 1;
  }
  delay(20);
}

#endif  // TLS_SPIKE
