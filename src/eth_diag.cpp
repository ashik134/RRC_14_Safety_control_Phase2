#include "eth_diag.h"

#if ETH_DIAG_ENABLED

#include <SPI.h>
#include <Ethernet.h>

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

// On this PLC the W5500 stays silent after power-up/reset until GPIO4 is
// driven (found by the sweep: it starts answering right after GPIO4 is
// toggled). GPIO4 is therefore treated as the W5500 reset/enable line: pulsed
// low then held high before the first SPI access. The vendor Ethernet library
// has no reset-pin support, so this is done here. -1 disables it.
#ifndef ETH_DIAG_RESET_PIN
#define ETH_DIAG_RESET_PIN 4
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
  digitalWrite(ETH_DIAG_RESET_PIN, HIGH);   // left driven high: chip out of reset
  delay(150);
  Serial.printf("[ETH] Hardware reset pulse on GPIO%d done\n", ETH_DIAG_RESET_PIN);
#endif
}

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
  uint64_t efuse = ESP.getEfuseMac();
  ethMac[0] = 0x02;
  ethMac[1] = (uint8_t)(efuse >> 0);
  ethMac[2] = (uint8_t)(efuse >> 8);
  ethMac[3] = (uint8_t)(efuse >> 16);
  ethMac[4] = (uint8_t)(efuse >> 24);
  ethMac[5] = (uint8_t)(efuse >> 32);

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
  }
  Serial.println("[ETH] ----------------------------------------");
}

void ethDiagPoll() {
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

EthDiagStatus ethDiagGetStatus() { return st; }

#else  // ETH_DIAG_ENABLED == 0

void ethDiagInit() {}
void ethDiagPoll() {}
EthDiagStatus ethDiagGetStatus() { return EthDiagStatus{false, 0, false, false, false}; }

#endif
