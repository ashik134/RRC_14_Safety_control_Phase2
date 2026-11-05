// Cloud heartbeat: tells the IntelliKran web app this PLC is online, and what
// state it is in, over the W5500 Ethernet port (IntelliKran docs/PLC_SYNC_API.md).
//
// It runs in its own low-priority task and is strictly one-way: it reports
// state and never touches outputs, E-STOP, BLE or the SD card, so losing the
// network or the cloud cannot affect crane control.
//
// The task starts only once the device login is entered in the local web panel,
// and then owns the W5500: the Ethernet library is not thread-safe, so from that
// point ethDiagPoll() runs in the task and loop() must not call it (see
// cloudLinkRunning()). Without a login, loop() polls the W5500 as it always did.
#pragma once

#include <Arduino.h>
#include "cloud_wire.h"

struct CloudLinkInfo {
  bool     configured;
  char     plcId[33];
  char     login[97];
  char     state[96];     // the last thing that happened, for the local panel
  bool     everOk;
  uint32_t lastOkAgoS;    // valid when everOk
  uint32_t okCount;
  uint32_t failCount;
};

void cloudLinkBegin();                               // once, at the end of setup()
void cloudLinkPublish(const CloudStatus &status);    // from loop(); cheap, never blocks
void cloudLinkGetInfo(CloudLinkInfo &info);
bool cloudLinkRunning();                             // true = the task owns the W5500
// False when the build sets no CLOUD_PROJECT_ID: nothing is ever sent, and the
// local web panel hides the Cloud Link page.
bool cloudLinkAvailable();

// The caller validates the values, and must be on loop()'s task (the web server
// is): saving can hand the W5500 over. Returns false if they could not be stored.
bool cloudLinkSave(const String &plcId, const String &login, const String &key, const String &apiKey);
void cloudLinkClear();

// ---- Firebase Realtime Database push (local web panel > Firebase) ----
// Same task and Ethernet port as above, but its own settings: the Device ID
// copied from the web app, the database secret and the database URL. While
// enabled and complete, the PLC writes its heartbeat and status to
// devices/{deviceId} every minute. Independent of CLOUD_PROJECT_ID.
struct FirebaseSettings {
  bool enabled;
  char deviceId[33];
  char secret[65];
  char dbUrl[97];
};

struct FirebaseInfo {
  bool     enabled;
  bool     complete;      // Device ID, secret and URL all present and valid
  bool     hasSecret;     // the secret itself is never handed to the page
  char     deviceId[33];
  char     dbUrl[97];
  char     state[96];
  bool     everOk;
  uint32_t lastOkAgoS;    // valid when everOk
  uint32_t okCount;
  uint32_t failCount;
};

// `cfg` includes the secret: for the web handler's validation only, never to show.
void cloudLinkGetFirebase(FirebaseSettings &cfg, FirebaseInfo &info);
// Same rules as cloudLinkSave(): the caller validates, and runs on loop()'s task.
bool cloudLinkSaveFirebase(const FirebaseSettings &next);
void cloudLinkClearFirebase();
