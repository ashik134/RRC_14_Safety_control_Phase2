// W5500 Ethernet bring-up / hardware-detect diagnostic.
//
// Self-contained and additive: it only talks to the W5500 (chip select
// GPIO14 on the 14IOS PLC, see PIN_SPI_SS_ETHERNET_LIB) and prints to
// Serial. It never touches the PLC I/O, BLE, WiFi or SD logic.
//
//   ethDiagInit()      - call once from setup(), after SD.begin() (shares VSPI)
//   ethDiagPoll()      - call often; rate-limited and non-blocking
//   ethDiagStartDhcp() - leave the static test address for a DHCP lease;
//                        blocks for up to ~8 s
//
// loop() polls until the cloud_link task starts, then only that task may call
// these: the Ethernet library has no locks, so two tasks must never share it.
//
// Compile it out entirely with -DETH_DIAG_ENABLED=0.
#pragma once

#include <Arduino.h>

#ifndef ETH_DIAG_ENABLED
#define ETH_DIAG_ENABLED 1
#endif

struct EthDiagStatus {
  bool    chipDetected;   // W5500 answered (raw VERSIONR == 0x04 and library init OK)
  uint8_t versionReg;     // raw VERSIONR value read over SPI (0x04 on a W5500)
  bool    linkUp;         // PHY link (cable connected to a live partner)
  bool    speed100;       // true = 100 Mbps, false = 10 Mbps (valid when linkUp)
  bool    fullDuplex;     // valid when linkUp
};

void ethDiagInit();
void ethDiagPoll();
bool ethDiagStartDhcp();   // true = lease obtained; false = back on the static address
EthDiagStatus ethDiagGetStatus();
