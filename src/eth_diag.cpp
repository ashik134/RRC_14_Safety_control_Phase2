#include "eth_diag.h"

#if ETH_DIAG_ENABLED

#include <SPI.h>
#include <Ethernet.h>
#include <Dns.h>

// W5500 chip select on the 14IOS PLC (same value the Ethernet library
// defaults to via PIN_SPI_SS_ETHERNET_LIB).
// Not const: the optional ETH_DIAG_SWEEP build can re-point it if the chip
// answers on a different pin.
#ifdef PIN_SPI_SS_ETHERNET_LIB
static uint8_t ETH_CS_PIN = PIN_SPI_SS_ETHERNET_LIB;
#else
static uint8_t ETH_CS_PIN = 14;
#endif

// Opt-in (build with -DETH_DIAG_SWEEP=1): if nothing answers on the vendor's
// chip-select, try other spare GPIOs as CS to find where the W5500 is wired.
// Skips every pin this PLC uses (Q0.x 12/25/26/27, I0.7/I0.8 32/33, SD CS 5,
// I2C 21/22, SPI 18/19/23, strap pin 0). Off by default: it drives GPIOs.
#ifndef ETH_DIAG_SWEEP
#define ETH_DIAG_SWEEP 0
#endif

// No reset line by default. GPIO4, which the sweep found the W5500 depends on,
// is not a reset: it switches the bus between the SD card and the W5500, and
// spi_bus_switch.cpp handles it on every transaction. Set a pin here to pulse
// one low then high before the first SPI access.
#ifndef ETH_DIAG_RESET_PIN
#define ETH_DIAG_RESET_PIN -1
#endif

// Static address: DHCP would block for up to a minute with no cable, which
// is unacceptable in safety control firmware. Override with -D if needed.
#ifndef ETH_DIAG_IP
#define ETH_DIAG_IP 192, 168, 1, 177
#endif

// W5500 common-register map (BSB 0).
static const uint16_t W5500_REG_SHAR     = 0x0009;  // source MAC, 6 bytes
static const uint16_t W5500_REG_PHYCFGR  = 0x002E;  // PHY status
static const uint16_t W5500_REG_VERSIONR = 0x0039;  // always 0x04 on a W5500
static const uint8_t  W5500_VERSION      = 0x04;

static const uint8_t PHYCFGR_LNK = 0x01;  // 1 = link up
static const uint8_t PHYCFGR_SPD = 0x02;  // 1 = 100 Mbps
static const uint8_t PHYCFGR_DPX = 0x04;  // 1 = full duplex

static const unsigned long POLL_INTERVAL_MS    = 1000;
static const unsigned long SUMMARY_INTERVAL_MS = 30000;

// Read-only TCP test server so a PC on the same switch can prove real
// two-way traffic (in addition to ICMP ping, which the W5500 answers in
// hardware once it has an IP). It never touches PLC I/O or safety state.
// Unauthenticated by design: for bench/commissioning tests on an isolated
// switch. Disable with -DETH_DIAG_TCP_PORT=0.
#ifndef ETH_DIAG_TCP_PORT
#define ETH_DIAG_TCP_PORT 5000
#endif

// Opt-in boot-time internet check (build with -DETH_DIAG_INTERNET_TEST=1).
// Runs once from ethDiagInit(), i.e. before BLE/WiFi/crane logic start, with
// hard time limits (worst case ~25 s extra boot time, ~8 s when no DHCP
// server answers), so it can never stall the running safety loop. Off by
// default because of that boot delay.
#ifndef ETH_DIAG_INTERNET_TEST
#define ETH_DIAG_INTERNET_TEST 0
#endif
static const char *netResult = "NOT_TESTED";   // reported by the TCP STATUS command

#if ETH_DIAG_TCP_PORT
static EthernetServer tcpServer(ETH_DIAG_TCP_PORT);
static bool           tcpStarted  = false;
static uint32_t       tcpRequests = 0;
#endif

static EthDiagStatus st = {false, 0x00, false, false, false};
static uint8_t       ethMac[6];
static bool          libInitOk = false;

// Raw W5500 SPI frame (variable-length data mode): 16-bit address, control
// byte (BSB<<3 | RWB<<2 | OM), then data. BSB=0 selects the common registers.
// Used instead of the Ethernet library so the detection result does not
// depend on any library behaviour. Slow clock keeps it tolerant of wiring.
static void w5500RawRead(uint16_t addr, uint8_t *out, uint8_t len) {
  SPI.beginTransaction(SPISettings(1000000, MSBFIRST, SPI_MODE0));
  digitalWrite(ETH_CS_PIN, LOW);
  SPI.transfer((uint8_t)(addr >> 8));
  SPI.transfer((uint8_t)(addr & 0xFF));
  SPI.transfer(0x00);                       // BSB=0 (common regs), read, VDM
  for (uint8_t i = 0; i < len; i++) out[i] = SPI.transfer(0x00);
  digitalWrite(ETH_CS_PIN, HIGH);
  SPI.endTransaction();
}

static uint8_t w5500RawRead8(uint16_t addr) {
  uint8_t v = 0;
  w5500RawRead(addr, &v, 1);
  return v;
}

// Locally-administered MAC derived from the ESP32 eFuse MAC. Fixed for the
// board's life, so ethDiagGetMac() can report it without waiting for init.
static void deriveEthMac(uint8_t *m) {
  uint64_t efuse = ESP.getEfuseMac();
  m[0] = 0x02;
  m[1] = (uint8_t)(efuse >> 0);
  m[2] = (uint8_t)(efuse >> 8);
  m[3] = (uint8_t)(efuse >> 16);
  m[4] = (uint8_t)(efuse >> 24);
  m[5] = (uint8_t)(efuse >> 32);
}

static void printMac(const uint8_t *m) {
  Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static uint8_t lastPhyCfgr = 0;

static void readPhy() {
  uint8_t phy = w5500RawRead8(W5500_REG_PHYCFGR);
  lastPhyCfgr   = phy;
  st.linkUp     = (phy & PHYCFGR_LNK) != 0;
  st.speed100   = (phy & PHYCFGR_SPD) != 0;
  st.fullDuplex = (phy & PHYCFGR_DPX) != 0;
}

static void printLink() {
  if (st.linkUp) {
    Serial.printf("[ETH] Link UP   - %s Mbps, %s duplex (PHYCFGR=0x%02X)\n",
                  st.speed100 ? "100" : "10", st.fullDuplex ? "full" : "half", lastPhyCfgr);
  } else {
    Serial.printf("[ETH] Link DOWN - W5500 is alive, no cable / no link partner (PHYCFGR=0x%02X)\n", lastPhyCfgr);
  }
}

// Hardware reset of the W5500 through its reset/enable pin, then the settle
// time the chip needs (PLL lock) before the first SPI access.
static void w5500HardwareReset() {
#if ETH_DIAG_RESET_PIN >= 0
  pinMode(ETH_DIAG_RESET_PIN, OUTPUT);
  digitalWrite(ETH_DIAG_RESET_PIN, LOW);
  delay(20);
  digitalWrite(ETH_DIAG_RESET_PIN, HIGH);
  delay(150);
  pinMode(ETH_DIAG_RESET_PIN, INPUT);
  Serial.printf("[ETH] Hardware reset pulse on GPIO%d done\n", ETH_DIAG_RESET_PIN);
#endif
}

#if ETH_DIAG_INTERNET_TEST
// HEAD / over plain HTTP; success = a "HTTP/1.x <code>" status line came back.
static bool httpHead(IPAddress ip, const char *host, char *statusLine, size_t statusLen) {
  statusLine[0] = '\0';
  EthernetClient c;
  c.setConnectionTimeout(3000);
  if (!c.connect(ip, 80)) {
    Serial.printf("[NET]   TCP connect to %s:80 FAILED (no route / blocked)\n", ip.toString().c_str());
    c.stop();
    return false;
  }
  c.print("HEAD / HTTP/1.0\r\nHost: ");
  c.print(host);
  c.print("\r\nConnection: close\r\n\r\n");
  unsigned long t0 = millis();
  while (!c.available() && c.connected() && millis() - t0 < 4000) delay(10);
  size_t n = 0;
  while (c.available() && n < statusLen - 1) {
    char ch = (char)c.read();
    if (ch == '\r' || ch == '\n') break;
    statusLine[n++] = ch;
  }
  statusLine[n] = '\0';
  c.stop();
  bool ok = strncmp(statusLine, "HTTP/", 5) == 0;
  Serial.printf("[NET]   TCP to %s:80 connected, reply: '%s' -> %s\n",
                ip.toString().c_str(), statusLine, ok ? "OK" : "NO HTTP REPLY");
  return ok;
}

static void internetTest() {
  Serial.println("[NET] ---- Internet access test (boot-time, time-limited) ----");

  // The PHY needs a moment after reset to bring the link up.
  for (int i = 0; i < 30 && !(readPhy(), st.linkUp); i++) delay(100);
  if (!st.linkUp) {
    Serial.println("[NET] Link is DOWN - cable/switch not connected. Test skipped.");
    netResult = "NO_LINK";
    return;
  }

  Serial.println("[NET] 1/4 DHCP: asking the network for an address, gateway and DNS...");
  unsigned long t0 = millis();
  bool dhcp = Ethernet.begin(ethMac, 8000, 2000) == 1;
  if (dhcp) {
    Serial.printf("[NET]   DHCP OK in %lu ms: ip=%s mask=%s gateway=%s dns=%s\n", millis() - t0,
                  Ethernet.localIP().toString().c_str(), Ethernet.subnetMask().toString().c_str(),
                  Ethernet.gatewayIP().toString().c_str(), Ethernet.dnsServerIP().toString().c_str());
  } else {
    // A failed lease leaves the chip at 0.0.0.0; restore the fixed address.
    Serial.printf("[NET]   DHCP FAILED after %lu ms - no DHCP server on this network\n", millis() - t0);
    Ethernet.begin(ethMac, IPAddress(ETH_DIAG_IP));
    Serial.printf("[NET]   Using fixed %s, gateway guessed %s (no internet unless that is your router)\n",
                  Ethernet.localIP().toString().c_str(), Ethernet.gatewayIP().toString().c_str());
  }

  char line[48];
  Serial.println("[NET] 2/4 Reach the internet by IP (no DNS): Cloudflare 1.1.1.1");
  bool byIp = httpHead(IPAddress(1, 1, 1, 1), "one.one.one.one", line, sizeof(line));

  Serial.println("[NET] 3/4 DNS: resolving example.com");
  DNSClient dns;
  dns.begin(Ethernet.dnsServerIP());
  IPAddress resolved;
  bool dnsOk = dns.getHostByName("example.com", resolved, 3000) == 1;
  if (dnsOk) Serial.printf("[NET]   example.com -> %s\n", resolved.toString().c_str());
  else       Serial.println("[NET]   DNS lookup FAILED (no DNS server reachable / no internet)");

  bool byName = false;
  if (dnsOk) {
    Serial.println("[NET] 4/4 HTTP request to example.com");
    byName = httpHead(resolved, "example.com", line, sizeof(line));
  } else {
    Serial.println("[NET] 4/4 skipped (DNS failed)");
  }

  if (byIp && byName) netResult = "OK";
  else if (byIp)      netResult = "OK_IP_ONLY_DNS_FAIL";
  else                netResult = "FAIL";
  Serial.printf("[NET] RESULT: internet %s  (dhcp=%s, by-IP=%s, dns=%s, by-name=%s)\n",
                byIp ? "REACHABLE" : "NOT REACHABLE", dhcp ? "yes" : "no",
                byIp ? "yes" : "no", dnsOk ? "yes" : "no", byName ? "yes" : "no");
  Serial.println("[NET] ---------------------------------------------------------");
}
#endif

void ethDiagInit() {
  Serial.println();
  Serial.println("[ETH] ---- W5500 Ethernet hardware check ----");
  Serial.printf("[ETH] Chip select = GPIO%u (shared VSPI bus: SCK18 MISO19 MOSI23)\n", ETH_CS_PIN);

  // Keep the W5500 deselected so it ignores SD/RTC-era bus traffic.
  pinMode(ETH_CS_PIN, OUTPUT);
  digitalWrite(ETH_CS_PIN, HIGH);
  SPI.begin();
  w5500HardwareReset();

  // Test 1: library-free raw SPI read of the chip-version register.
  st.versionReg = w5500RawRead8(W5500_REG_VERSIONR);
  bool rawOk = (st.versionReg == W5500_VERSION);
  Serial.printf("[ETH] Raw SPI read VERSIONR(0x0039) = 0x%02X (expect 0x%02X) -> %s\n",
                st.versionReg, W5500_VERSION, rawOk ? "OK" : "FAIL");
#if ETH_DIAG_SWEEP
  if (!rawOk) {
    static const uint8_t candidates[] = {15, 2, 4, 13, 16, 17};
    Serial.println("[ETH] Sweep: no answer on default CS, trying other spare GPIOs...");
    for (uint8_t c : candidates) {
      if (c == ETH_CS_PIN || c == ETH_DIAG_RESET_PIN) continue;
      pinMode(c, OUTPUT);
      digitalWrite(c, HIGH);
      uint8_t saved = ETH_CS_PIN;
      ETH_CS_PIN = c;
      uint8_t v = w5500RawRead8(W5500_REG_VERSIONR);
      ETH_CS_PIN = saved;
      // Also re-read on the default CS after driving pin c: if that suddenly
      // answers, pin c (or the extra bus traffic) is what woke the chip.
      uint8_t vDefault = w5500RawRead8(W5500_REG_VERSIONR);
      Serial.printf("[ETH] Sweep: CS=GPIO%u -> VERSIONR=0x%02X | default CS GPIO%u now reads 0x%02X\n",
                    c, v, saved, vDefault);
      if (v == W5500_VERSION) {
        ETH_CS_PIN = c;
        st.versionReg = v;
        rawOk = true;
        Serial.printf("[ETH] Sweep: W5500 FOUND with chip select on GPIO%u\n", c);
        break;
      }
      pinMode(c, INPUT);   // back to the reset-state high-impedance input
      if (vDefault == W5500_VERSION) {
        st.versionReg = vDefault;
        rawOk = true;
        Serial.printf("[ETH] Sweep: W5500 started answering on GPIO%u right after GPIO%u was driven - that pin may release its reset/enable\n",
                      saved, c);
        break;
      }
    }
  }
#endif

  // Locally-administered MAC derived from the ESP32 eFuse MAC: unique per
  // board, no collision with a real vendor OUI.
  deriveEthMac(ethMac);

  // Test 2: the Ethernet library's own init (soft reset, MR write/readback
  // pattern test, chip-ID check), then program MAC + static IP.
  Ethernet.init(ETH_CS_PIN);
  Ethernet.begin(ethMac, IPAddress(ETH_DIAG_IP));
  EthernetHardwareStatus hw = Ethernet.hardwareStatus();
  libInitOk = (hw == EthernetW5500);
  Serial.printf("[ETH] Ethernet library init -> %s\n",
                hw == EthernetW5500 ? "W5500 detected"
                : hw == EthernetW5200 ? "W5200 detected (unexpected)"
                : hw == EthernetW5100 ? "W5100 detected (unexpected)"
                                      : "NO HARDWARE");

  // Test 3: write/read round trip - the MAC we just programmed must read
  // back identically from the chip's SHAR register.
  uint8_t macBack[6] = {0};
  if (libInitOk) {
    w5500RawRead(W5500_REG_SHAR, macBack, 6);
    bool macOk = memcmp(macBack, ethMac, 6) == 0;
    Serial.print("[ETH] MAC written ");
    printMac(ethMac);
    Serial.print(" / read back ");
    printMac(macBack);
    Serial.printf(" -> %s\n", macOk ? "MATCH (SPI write+read OK)" : "MISMATCH");
    libInitOk = macOk;
  }

  // Final verdict uses a fresh raw read taken after the library init. The
  // chip can start answering part-way through boot, so the first probe alone
  // must not decide the result.
  st.versionReg = w5500RawRead8(W5500_REG_VERSIONR);
  rawOk = (st.versionReg == W5500_VERSION);
  Serial.printf("[ETH] Raw SPI re-read VERSIONR after init = 0x%02X -> %s\n",
                st.versionReg, rawOk ? "OK" : "FAIL");
  if (!rawOk) {
    if (st.versionReg == 0x00 || st.versionReg == 0xFF) {
      Serial.println("[ETH]   Bus reads 0x00/0xFF: no device driving MISO - check W5500 power, reset, CS wiring, SPI lines.");
    } else {
      Serial.println("[ETH]   Unexpected value: a device answers but it is not a W5500 (or bus noise).");
    }
  }

  st.chipDetected = rawOk && libInitOk;
  readPhy();

  Serial.printf("[ETH] RESULT: W5500 %s\n",
                st.chipDetected ? "DETECTED - Ethernet hardware is responding"
                                : "NOT DETECTED - Ethernet hardware is not responding");
  if (st.chipDetected) {
    Serial.printf("[ETH] Static IP %s\n", Ethernet.localIP().toString().c_str());
    printLink();
#if ETH_DIAG_INTERNET_TEST
    internetTest();
#endif
#if ETH_DIAG_TCP_PORT
    // Bound the worst-case time a send to a vanished peer can block loop().
    Ethernet.setRetransmissionTimeout(100);
    Ethernet.setRetransmissionCount(3);
    tcpServer.begin();
    tcpStarted = true;
    Serial.printf("[ETH] Test server listening on %s:%u (TCP: PING, STATUS, HELP; ICMP ping also answered)\n",
                  Ethernet.localIP().toString().c_str(), (unsigned)ETH_DIAG_TCP_PORT);
#endif
  }
  Serial.println("[ETH] ----------------------------------------");
}

#if ETH_DIAG_TCP_PORT
// One short command per packet, e.g. from `nc`/telnet/PowerShell. Non-blocking
// apart from the tiny reply write; handles at most one request per call.
static void serveTcp() {
  if (!tcpStarted) return;
  EthernetClient c = tcpServer.available();
  if (!c) return;

  char buf[48];
  int n = c.read((uint8_t *)buf, sizeof(buf) - 1);
  if (n <= 0) return;
  while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == ' ')) n--;
  buf[n] = '\0';
  for (int i = 0; i < n; i++) buf[i] = toupper((unsigned char)buf[i]);

  tcpRequests++;
  Serial.printf("[ETH] TCP request #%lu from %s: '%s'\n",
                (unsigned long)tcpRequests, c.remoteIP().toString().c_str(), buf);

  if (strcmp(buf, "PING") == 0) {
    c.print("PONG\r\n");
  } else if (strcmp(buf, "STATUS") == 0) {
    c.printf("OK uptime_s=%lu link=%s speed=%s duplex=%s ip=%s internet=%s free_heap=%u requests=%lu\r\n",
             millis() / 1000UL, st.linkUp ? "UP" : "DOWN",
             st.speed100 ? "100" : "10", st.fullDuplex ? "full" : "half",
             Ethernet.localIP().toString().c_str(), netResult,
             (unsigned)ESP.getFreeHeap(), (unsigned long)tcpRequests);
  } else if (strcmp(buf, "HELP") == 0) {
    c.print("Commands: PING, STATUS, HELP (read-only)\r\n");
  } else {
    c.print("ERR unknown command. Commands: PING, STATUS, HELP\r\n");
  }
}
#endif

void ethDiagPoll() {
#if ETH_DIAG_TCP_PORT
  serveTcp();   // every loop() so replies are prompt; cheap when idle
#endif

  static unsigned long lastPollMs    = 0;
  static unsigned long lastSummaryMs = 0;
  static bool          lastLink      = false;
  static bool          lastSpeed     = false;
  static bool          lastDuplex    = false;
  static bool          lastAlive     = st.chipDetected;  // report only changes after init
  static bool          first         = true;

  unsigned long now = millis();
  if (now - lastPollMs < POLL_INTERVAL_MS) return;
  lastPollMs = now;

  // Two register reads at 1 MHz: well under a millisecond, never blocks.
  uint8_t ver = w5500RawRead8(W5500_REG_VERSIONR);
  bool alive = (ver == W5500_VERSION);
  st.versionReg = ver;

  if (alive != lastAlive) {
    lastAlive = alive;
    Serial.printf("[ETH] W5500 %s (VERSIONR=0x%02X)\n",
                  alive ? "is responding again" : "STOPPED responding", ver);
  }
  if (!alive) {
    st.linkUp = false;
    return;
  }

  readPhy();
  if (first || st.linkUp != lastLink || (st.linkUp && (st.speed100 != lastSpeed || st.fullDuplex != lastDuplex))) {
    first = false;
    lastLink   = st.linkUp;
    lastSpeed  = st.speed100;
    lastDuplex = st.fullDuplex;
    printLink();
  }

  if (now - lastSummaryMs >= SUMMARY_INTERVAL_MS) {
    lastSummaryMs = now;
    Serial.printf("[ETH] alive: VERSIONR=0x%02X, link %s\n", ver, st.linkUp ? "UP" : "DOWN");
  }
}

// The chip is not reset by this (W5100.init() only runs once), so the test
// server's listening socket survives and must not be opened a second time.
bool ethDiagStartDhcp() {
  // Only the cloud task calls this, so nothing here can hold up loop() and the
  // W5500 defaults, which suit an internet path, can come back.
  Ethernet.setRetransmissionTimeout(200);
  Ethernet.setRetransmissionCount(8);
  bool dhcp = Ethernet.begin(ethMac, 8000, 2000) == 1;
  if (dhcp) {
    Serial.printf("[ETH] DHCP OK: ip=%s gateway=%s dns=%s\n", Ethernet.localIP().toString().c_str(),
                  Ethernet.gatewayIP().toString().c_str(), Ethernet.dnsServerIP().toString().c_str());
  } else {
    Ethernet.begin(ethMac, IPAddress(ETH_DIAG_IP));   // a failed lease leaves the chip at 0.0.0.0
  }
  return dhcp;
}

EthDiagStatus ethDiagGetStatus() { return st; }

void ethDiagGetMac(char *out, size_t cap) {
  uint8_t m[6];
  deriveEthMac(m);
  snprintf(out, cap, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

#else  // ETH_DIAG_ENABLED == 0

void ethDiagInit() {}
void ethDiagPoll() {}
bool ethDiagStartDhcp() { return false; }
EthDiagStatus ethDiagGetStatus() { return EthDiagStatus{false, 0, false, false, false}; }
void ethDiagGetMac(char *out, size_t cap) { if (cap) out[0] = ' '; }

#endif
