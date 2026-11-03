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
  char     rtc[20];       // "YYYY-MM-DD HH:MM:SS", empty when the clock is unset
  bool     rtcOk;
  bool     sdOk;
  bool     estop;         // true while the E-STOP is engaged (firmware's motionEstop)
  bool     up, down, left, right;
  bool     bleConn;
  bool     bleAuth;
  char     bleUser[64];
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
