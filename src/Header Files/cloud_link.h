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
  // Sync with the web app (see cloudLinkLoop()).
  char     phoneState[96];
  char     userState[96];
  char     networkState[96];
  char     eventState[96];    // event upload
  bool     phoneEverOk;       // any sync request succeeded
  uint32_t phoneLastOkAgoS;   // valid when phoneEverOk
};

// `cfg` includes the secret: for the web handler's validation only, never to show.
void cloudLinkGetFirebase(FirebaseSettings &cfg, FirebaseInfo &info);
// Same rules as cloudLinkSave(): the caller validates, and runs on loop()'s task.
bool cloudLinkSaveFirebase(const FirebaseSettings &next);
void cloudLinkClearFirebase();

// ---- Sync with the web app (BLE Face Access section) ----
// While the Firebase push is on, the network task also keeps the Device
// Registry (devices[]), the users (users[]) and the network settings in step
// with the web app, the way the MA devices do it (paths in cloud_wire.h):
//  * web -> PLC: it polls devices/{id}/tobesynced; when true it clears it and
//    reads the queues tobesyncedphoneid, tobesyncedusers and
//    tobesyncednetwork. Each entry is applied here, then deleted, or marked
//    {status: "rejected", reason}. Every run that applied something is
//    logged in devices/{id}/synchistory.
//  * PLC -> web: phones and users added, changed or deleted on the PLC (its
//    web page, the mobile app) are written to phonelist / userlist (source
//    "plc", never a password). After each boot the lists are compared: the
//    PLC's entries are written, and entries the PLC does not have and that
//    are not waiting in a queue are removed.
// It never touches outputs, E-STOP or the BLE link: a phone or user change
// applies from the next BLE login on, like a change made on the local web
// page. New network settings are applied by a restart, only once no phone has
// been connected for 10 s (main.cpp).

// Call from loop() on every pass while cloudLinkRunning(). This is where the
// lists are changed and read for the network task, so devices[] and users[]
// are only ever changed from loop()'s task. Cheap when there is nothing to do.
void cloudLinkLoop();

// A phone was registered (removed = false) or deleted on the PLC.
// From loop()'s task, after the change has been saved.
void cloudLinkPhoneChanged(const char *phoneId, const char *owner, bool removed);

// A user was added or changed (`now`, after saving) and/or removed
// (`removedEmail`: a deleted user, or a changed email's old value) on the PLC.
// From loop()'s task. Never sends the password.
struct User;
void cloudLinkUserChanged(const User *now, const char *removedEmail);

// ---- Event upload (the web app's "Events & Logs" section) ----
// Every SD event-log line (logEvent()) is also queued for bfa_logs, and every
// BLE login for bfa_events (layout in cloud_wire.h). The network task uploads
// them a few at a time. The queue is in RAM: if it fills while the database
// cannot be reached, the oldest entries are dropped (they stay on the SD
// card, and the next uploaded line says how many were skipped). Events with
// no valid clock time are not uploaded. Cheap; from loop()'s task.
void cloudLinkLogEvent(const char *ts, const char *category, const char *detail);
void cloudLinkAccessEvent(const char *ts, bool authorized, const char *email, const char *name, const char *role,
                          const char *empId, const char *phoneId, const char *reason, unsigned suppressed);
