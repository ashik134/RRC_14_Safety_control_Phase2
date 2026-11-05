#include "web_handler.h"
#include <Update.h>
#include <SD.h>
#include "web_logo.h"
#include "cloud_link.h"

// Drop-in replacement for webServer.send(...), used everywhere in this file
// instead of calling it directly.
//
// A client that silently vanishes mid-session — WiFi range lost, app
// killed, a bad moment of WiFi/BLE radio coexistence contention — leaves
// no FIN/RST for the ESP32's TCP stack to notice, so the socket still
// looks "connected" with nothing locally wrong to detect in advance.
// Writing to it then runs into WiFiClient::write()'s own internal retry
// loop: up to 10 attempts, each waiting up to 1 second for the socket to
// become writable, so a single send() can block this task for up to ~10
// seconds — and that loop never actually closes the socket on a plain
// timeout, only for a handful of specific hard errors. Left alone, the
// same zombie connection gets retried again on the next request that
// reaches it, and keeps one of the ESP32's very few sockets pinned
// indefinitely, which is what "site can't be reached" for a new visitor
// actually is: no free socket left to accept them.
//
// There's no way to detect this case beforehand, so this times the actual
// write instead: a write on a healthy local AP link should take single-
// digit milliseconds, so anything far beyond that is treated as proof the
// peer is gone, and the connection is force-closed right then rather than
// left to be retried again later.
static void sendSafe(int code, const char *contentType = NULL, const String &content = String(""))
{
  unsigned long writeStartMs = millis();
  webServer.send(code, contentType, content);
  unsigned long writeMs = millis() - writeStartMs;
  if (writeMs > 300)
  {
    Serial.printf("Web: client write took %lums — treating connection as dead, closing it\n", writeMs);
    webServer.client().stop();
  }
}

// Same dead-client guard as sendSafe(), for a response streamed straight from
// flash with send_P() — used for the (large) stylesheet and the logo so they
// are never copied into a RAM String first. Pass `length` for binary data: the
// 3-argument send_P() measures the content with strlen_P(), which would stop at
// the first 0x00 byte of a PNG.
static void sendSafeP(int code, const char *contentType, const char *content, size_t length = 0)
{
  unsigned long writeStartMs = millis();
  if (length > 0)
    webServer.send_P(code, contentType, content, length);
  else
    webServer.send_P(code, contentType, content);
  unsigned long writeMs = millis() - writeStartMs;
  if (writeMs > 300)
  {
    Serial.printf("Web: client write took %lums — treating connection as dead, closing it\n", writeMs);
    webServer.client().stop();
  }
}

#define MAX_SESSIONS 5
struct WebSession
{
  String token;
  String role;             // "Admin" / "Operator"
  String userEmail;        // empty = web admin, else BLE user email
  bool timeExempt = false; // true for admin "Login As": skips the timed-access window check
};
static WebSession sessions[MAX_SESSIONS];
static int sessionNext = 0; // round-robin eviction counter

// Device registry
Device devices[MAX_DEVICES];
int deviceCount = 0;

void loadDevices()
{
  prefs.begin("devices", true);
  deviceCount = prefs.getInt("count", 0);
  if (deviceCount < 0)
    deviceCount = 0;
  if (deviceCount > MAX_DEVICES)
    deviceCount = MAX_DEVICES;
  for (int i = 0; i < deviceCount; i++)
  {
    char idkey[16], okey[16];
    sprintf(idkey, "dev_%d", i);
    sprintf(okey, "owner_%d", i);
    prefs.getString(idkey, devices[i].id, sizeof(devices[i].id));
    prefs.getString(okey, devices[i].owner, sizeof(devices[i].owner));
  }
  prefs.end();
}

void saveDevices()
{
  prefs.begin("devices", false);
  prefs.putInt("count", deviceCount);
  for (int i = 0; i < deviceCount; i++)
  {
    char idkey[16], okey[16];
    sprintf(idkey, "dev_%d", i);
    sprintf(okey, "owner_%d", i);
    prefs.putString(idkey, devices[i].id);
    prefs.putString(okey, devices[i].owner);
  }
  prefs.end();
}

bool isDeviceRegistered(const char *id)
{
  if (!id || id[0] == '\0')
    return false;
  for (int i = 0; i < deviceCount; i++)
  {
    if (strcmp(devices[i].id, id) == 0)
      return true;
  }
  return false;
}

bool registerDevice(const char *id, const char *owner)
{
  if (!id || id[0] == '\0')
    return false;
  if (strlen(id) > 40)
    return false;
  if (isDeviceRegistered(id))
    return false;
  if (deviceCount >= MAX_DEVICES)
    return false;
  strncpy(devices[deviceCount].id, id, sizeof(devices[deviceCount].id));
  devices[deviceCount].id[sizeof(devices[deviceCount].id) - 1] = '\0';
  if (owner)
    strncpy(devices[deviceCount].owner, owner, sizeof(devices[deviceCount].owner));
  else
    devices[deviceCount].owner[0] = '\0';
  devices[deviceCount].owner[sizeof(devices[deviceCount].owner) - 1] = '\0';
  deviceCount++;
  saveDevices();
  return true;
}

bool unregisterDevice(const char *id)
{
  if (!id)
    return false;
  for (int i = 0; i < deviceCount; i++)
  {
    if (strcmp(devices[i].id, id) == 0)
    {
      for (int j = i; j < deviceCount - 1; j++)
      {
        devices[j] = devices[j + 1];
      }
      deviceCount--;
      saveDevices();
      return true;
    }
  }
  return false;
}

// Web admin credentials (mutable, persisted in NVS namespace "webadmin")
static char webAdminUser[64] = "superadmin@plc.com";
static char webAdminPass[64] = "superadmin123";

static void loadWebAdmin()
{
  prefs.begin("webadmin", true);
  String u = prefs.getString("user", "superadmin@plc.com");
  String p = prefs.getString("pass", "superadmin123");
  prefs.end();
  // Migrate stale NVS that stored a plain username (no @) — reset to email default
  if (u.indexOf('@') < 0)
  {
    u = "superadmin@plc.com";
    p = "superadmin123";
    prefs.begin("webadmin", false);
    prefs.putString("user", u);
    prefs.putString("pass", p);
    prefs.end();
    Serial.println("Web admin migrated to email login (superadmin@plc.com / superadmin123)");
  }
  u.toCharArray(webAdminUser, sizeof(webAdminUser));
  p.toCharArray(webAdminPass, sizeof(webAdminPass));
}

static void saveWebAdmin()
{
  prefs.begin("webadmin", false);
  prefs.putString("user", webAdminUser);
  prefs.putString("pass", webAdminPass);
  prefs.end();
}

static String generateToken()
{
  char buf[33];
  for (int i = 0; i < 32; i++)
  {
    buf[i] = "0123456789abcdef"[random(16)];
  }
  buf[32] = '\0';
  return String(buf);
}

static String getSessionCookie()
{
  String cookieHeader = webServer.header("Cookie");
  int idx = cookieHeader.indexOf("session=");
  if (idx < 0)
    return "";
  int start = idx + 8;
  int end = cookieHeader.indexOf(';', start);
  if (end < 0)
    return cookieHeader.substring(start);
  return cookieHeader.substring(start, end);
}

// Find session slot for the current request cookie; returns -1 if not found
static int findSessionIdx()
{
  String cookie = getSessionCookie();
  if (cookie.length() == 0)
    return -1;
  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token.length() > 0 && sessions[i].token == cookie)
      return i;
  }
  return -1;
}
// Helpers: role and email for the current request
static String currentRole()
{
  int i = findSessionIdx();
  return i >= 0 ? sessions[i].role : "";
}
static String currentUserEmail()
{
  int i = findSessionIdx();
  return i >= 0 ? sessions[i].userEmail : "";
}
// ---- Timed-access helpers ----
// Formats a timestamp as "YYYY-MM-DD HH:MM", or as "YYYY-MM-DDTHH:MM" (the
// value format of <input type='datetime-local'>) when `forInput` is true.
static String formatDateTime(uint32_t ts, bool forInput = false)
{
  time_t t = (time_t)ts;
  struct tm tmv;
  gmtime_r(&t, &tmv);
  char buf[20];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d%c%02d:%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
           forInput ? 'T' : ' ', tmv.tm_hour, tmv.tm_min);
  return String(buf);
}

// Parses "YYYY-MM-DDTHH:MM" (from <input type='datetime-local'>) into seconds
// since 1970, treating the fields as literal RTC date/time (no time zone).
bool parseDateTimeLocal(const String &s, uint32_t &ts)
{
  if (s.length() < 16 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':')
    return false;
  int y = s.substring(0, 4).toInt();
  int mo = s.substring(5, 7).toInt();
  int d = s.substring(8, 10).toInt();
  int h = s.substring(11, 13).toInt();
  int mi = s.substring(14, 16).toInt();
  if (y < 2000 || y > 2099 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59)
    return false;
  // Days since 1970-01-01 for the given civil date (proleptic Gregorian).
  int yy = mo <= 2 ? y - 1 : y;
  int era = yy / 400;
  int yoe = yy - era * 400;
  int doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  long days = (long)era * 146097 + doe - 719468;
  ts = (uint32_t)(days * 86400L + h * 3600L + mi * 60L);
  return true;
}

// Reads accessType/from/to from the Add/Edit form into `u`. Returns an error
// message, or an empty string on success.
static String readAccessFromForm(User &u)
{
  if (webServer.arg("accessType") != "timed")
  {
    u.accessType = ACCESS_PERPETUAL;
    u.startTs = 0;
    u.endTs = 0;
    return "";
  }
  uint32_t from, to;
  if (!parseDateTimeLocal(webServer.arg("fromTime"), from) || !parseDateTimeLocal(webServer.arg("toTime"), to))
    return "Timed access requires both a From and a To date and time.";
  if (to <= from)
    return "Timed access: the To date and time must be after the From date and time.";
  u.accessType = ACCESS_TIMED;
  u.startTs = from;
  u.endTs = to;
  return "";
}

// Allocate a slot — prefers empty, else evicts round-robin
static int allocSessionSlot()
{
  for (int i = 0; i < MAX_SESSIONS; i++)
  {
    if (sessions[i].token.length() == 0)
      return i;
  }
  int slot = sessionNext;
  sessionNext = (sessionNext + 1) % MAX_SESSIONS;
  return slot;
}

// ============================================================
//  Stylesheet  (GET /style.css — streamed straight from flash)
// ============================================================
// Bump CSS_VER whenever HTML_STYLE changes: it is both the ?v= on every page's
// <link> and the ETag, so browsers drop their cached copy.
//
// Icons are Feather-style 24x24 outline glyphs inlined as data-URI masks, so the
// UI needs no network (the PLC's own Wi-Fi has no internet) and every icon takes
// the colour of its text. Markup: <i class='ic ic-home'></i>.
#define CSS_VER "5"
// Bump LOGO_VER whenever src/web_logo.h is regenerated (tools/make_web_logo.py).
#define LOGO_VER "1"
#define SVG_OPEN "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E"
#define SVG_CLOSE "%3C/svg%3E\")"
#define SVG_ICON(name, shapes) ".ic-" name "{--ico:" SVG_OPEN shapes SVG_CLOSE "}\n"
#define S_PATH(d) "%3Cpath d='" d "'/%3E"
#define S_POLY(p) "%3Cpolyline points='" p "'/%3E"
#define S_GON(p) "%3Cpolygon points='" p "'/%3E"
#define S_LINE(x1, y1, x2, y2) "%3Cline x1='" #x1 "' y1='" #y1 "' x2='" #x2 "' y2='" #y2 "'/%3E"
#define S_CIRC(cx, cy, r) "%3Ccircle cx='" #cx "' cy='" #cy "' r='" #r "'/%3E"
#define S_RECT(x, y, w, h, rx) "%3Crect x='" #x "' y='" #y "' width='" #w "' height='" #h "' rx='" #rx "'/%3E"
#define S_ELL(cx, cy, rx, ry) "%3Cellipse cx='" #cx "' cy='" #cy "' rx='" #rx "' ry='" #ry "'/%3E"

static const char HTML_STYLE[] =
    R"CSS(:root{--brand:#1565C0;--brand-dark:#0B3D91;--brand-ink:#0F2E5C;--brand-50:#EFF6FF;--brand-100:#DBEAFE;--brand-200:#BFDBFE;
--ink:#0F172A;--text:#1E293B;--soft:#475569;--faint:#64748B;--line:#E2E8F0;--line-2:#CBD5E1;--bg:#F1F5F9;--tint:#F8FAFC;
--ok:#16A34A;--ok-bg:#ECFDF3;--ok-ink:#166534;--ok-line:#BBF7D0;
--warn:#EA580C;--warn-bg:#FFF7ED;--warn-ink:#9A3412;--warn-line:#FED7AA;
--danger:#DC2626;--danger-dark:#B91C1C;--danger-bg:#FEF2F2;--danger-ink:#991B1B;--danger-line:#FECACA;
--topbar:60px;--side:252px;--fs-input:14.5px;
--shadow-sm:0 1px 2px rgba(15,23,42,.06),0 1px 1px rgba(15,23,42,.03);--shadow-md:0 10px 28px rgba(15,23,42,.14);--shadow-lg:0 24px 60px rgba(2,12,40,.38);
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--brand)}
button,input,select,textarea{font:inherit;color:inherit}
button{cursor:pointer}
.grow{flex:1}
.ic{display:inline-block;flex:none;width:18px;height:18px;vertical-align:-3px;background-color:currentColor;-webkit-mask-image:var(--ico);mask-image:var(--ico);-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;-webkit-mask-position:center;mask-position:center;-webkit-mask-size:contain;mask-size:contain}
)CSS"
    // ---- icon set ----
    SVG_ICON("home", S_PATH("M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z") S_POLY("9 22 9 12 15 12 15 22"))
        SVG_ICON("users", S_PATH("M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2") S_CIRC(9, 7, 4) S_PATH("M23 21v-2a4 4 0 0 0-3-3.87") S_PATH("M16 3.13a4 4 0 0 1 0 7.75"))
            SVG_ICON("user", S_PATH("M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2") S_CIRC(12, 7, 4))
                SVG_ICON("phone", S_RECT(5, 2, 14, 20, 2) S_LINE(12, 18, 12.01, 18))
                    SVG_ICON("cloud", S_POLY("16 16 12 12 8 16") S_LINE(12, 12, 12, 21) S_PATH("M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"))
                        SVG_ICON("folder", S_PATH("M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"))
                            SVG_ICON("file", S_PATH("M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z") S_POLY("14 2 14 8 20 8") S_LINE(16, 13, 8, 13) S_LINE(16, 17, 8, 17))
                                SVG_ICON("sliders", S_LINE(4, 21, 4, 14) S_LINE(4, 10, 4, 3) S_LINE(12, 21, 12, 12) S_LINE(12, 8, 12, 3) S_LINE(20, 21, 20, 16) S_LINE(20, 12, 20, 3) S_LINE(1, 14, 7, 14) S_LINE(9, 8, 15, 8) S_LINE(17, 16, 23, 16))
                                    SVG_ICON("cpu", S_RECT(4, 4, 16, 16, 2) S_RECT(9, 9, 6, 6, 0) S_LINE(9, 1, 9, 4) S_LINE(15, 1, 15, 4) S_LINE(9, 20, 9, 23) S_LINE(15, 20, 15, 23) S_LINE(20, 9, 23, 9) S_LINE(20, 14, 23, 14) S_LINE(1, 9, 4, 9) S_LINE(1, 14, 4, 14))
                                        SVG_ICON("wifi", S_PATH("M5 12.55a11 11 0 0 1 14.08 0") S_PATH("M1.42 9a16 16 0 0 1 21.16 0") S_PATH("M8.53 16.11a6 6 0 0 1 6.95 0") S_LINE(12, 20, 12.01, 20))
                                            SVG_ICON("clock", S_CIRC(12, 12, 10) S_POLY("12 6 12 12 16 14"))
                                                SVG_ICON("logout", S_PATH("M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4") S_POLY("16 17 21 12 16 7") S_LINE(21, 12, 9, 12))
                                                    SVG_ICON("login", S_PATH("M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4") S_POLY("10 17 15 12 10 7") S_LINE(15, 12, 3, 12))
                                                        SVG_ICON("key", S_PATH("M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"))
                                                            SVG_ICON("plus", S_LINE(12, 5, 12, 19) S_LINE(5, 12, 19, 12))
                                                                SVG_ICON("edit", S_PATH("M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"))
                                                                    SVG_ICON("trash", S_POLY("3 6 5 6 21 6") S_PATH("M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6") S_LINE(10, 11, 10, 17) S_LINE(14, 11, 14, 17) S_PATH("M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"))
                                                                        SVG_ICON("download", S_PATH("M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4") S_POLY("7 10 12 15 17 10") S_LINE(12, 15, 12, 3))
                                                                            SVG_ICON("upload", S_PATH("M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4") S_POLY("17 8 12 3 7 8") S_LINE(12, 3, 12, 15))
                                                                                SVG_ICON("check", S_POLY("20 6 9 17 4 12"))
                                                                                    SVG_ICON("check-circle", S_PATH("M22 11.08V12a10 10 0 1 1-5.93-9.14") S_POLY("22 4 12 14.01 9 11.01"))
                                                                                        SVG_ICON("alert", S_PATH("M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z") S_LINE(12, 9, 12, 13) S_LINE(12, 17, 12.01, 17))
                                                                                            SVG_ICON("alert-circle", S_CIRC(12, 12, 10) S_LINE(12, 8, 12, 12) S_LINE(12, 16, 12.01, 16))
                                                                                                SVG_ICON("info", S_CIRC(12, 12, 10) S_LINE(12, 16, 12, 12) S_LINE(12, 8, 12.01, 8))
                                                                                                    SVG_ICON("left", S_LINE(19, 12, 5, 12) S_POLY("12 19 5 12 12 5"))
                                                                                                        SVG_ICON("right", S_LINE(5, 12, 19, 12) S_POLY("12 5 19 12 12 19"))
                                                                                                            SVG_ICON("up", S_LINE(12, 19, 12, 5) S_POLY("5 12 12 5 19 12"))
                                                                                                                SVG_ICON("down", S_LINE(12, 5, 12, 19) S_POLY("19 12 12 19 5 12"))
                                                                                                                    SVG_ICON("chev", S_POLY("6 9 12 15 18 9"))
                                                                                                                        SVG_ICON("menu", S_LINE(3, 12, 21, 12) S_LINE(3, 6, 21, 6) S_LINE(3, 18, 21, 18))
                                                                                                                            SVG_ICON("eye", S_PATH("M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z") S_CIRC(12, 12, 3))
                                                                                                                                SVG_ICON("eye-off", S_PATH("M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24") S_LINE(1, 1, 23, 23))
                                                                                                                                    SVG_ICON("shield", S_PATH("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"))
                                                                                                                                        SVG_ICON("bluetooth", S_POLY("6.5 6.5 17.5 17.5 12 23 12 1 17.5 6.5 6.5 17.5"))
                                                                                                                                            SVG_ICON("database", S_ELL(12, 5, 9, 3) S_PATH("M21 12c0 1.66-4 3-9 3s-9-1.34-9-3") S_PATH("M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"))
                                                                                                                                                SVG_ICON("octagon", S_GON("7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2") S_LINE(12, 8, 12, 12) S_LINE(12, 16, 12.01, 16))
                                                                                                                                                    SVG_ICON("activity", S_POLY("22 12 18 12 15 21 9 3 6 12 2 12"))
                                                                                                                                                        R"CSS(
/* ---- top bar ---- */
.topbar{position:sticky;top:0;z-index:70;height:var(--topbar);display:flex;align-items:center;gap:12px;padding:0 22px;background:linear-gradient(90deg,var(--brand-ink),var(--brand-dark));color:#fff;box-shadow:0 2px 10px rgba(11,36,71,.28)}
.menu-btn{display:none;width:42px;height:42px;margin-left:-8px;border:0;border-radius:11px;background:transparent;color:#fff;align-items:center;justify-content:center}
.menu-btn .ic{width:24px;height:24px}
.menu-btn:hover{background:rgba(255,255,255,.12)}
.brand{display:flex;align-items:center;gap:11px;min-width:0;color:#fff;text-decoration:none}
.brand-logo{display:block;flex:none;width:40px;height:40px;filter:drop-shadow(0 2px 6px rgba(0,0,0,.32))}
.brand-text{min-width:0}
.brand-name{display:block;font-size:17px;font-weight:700;letter-spacing:.6px;line-height:1.1;white-space:nowrap}
.brand-sub{display:block;margin-top:2px;font-size:11px;font-weight:500;letter-spacing:.4px;color:rgba(255,255,255,.66);white-space:nowrap}
.user-menu{position:relative}
.user-btn{display:flex;align-items:center;gap:10px;height:44px;padding:0 12px 0 6px;border:1px solid rgba(255,255,255,.22);border-radius:13px;background:rgba(255,255,255,.08);color:#fff;transition:background .15s}
.user-btn:hover,.user-btn[aria-expanded=true]{background:rgba(255,255,255,.17)}
.user-btn .ic{width:15px;height:15px;opacity:.8}
.avatar{flex:none;width:32px;height:32px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#60A5FA,#2563EB);color:#fff;font-size:13.5px;font-weight:700}
.user-meta{display:flex;flex-direction:column;align-items:flex-start;min-width:0;max-width:210px;line-height:1.2;text-align:left}
.user-meta b{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13.5px;font-weight:600}
.user-meta small{font-size:11px;font-weight:500;color:rgba(255,255,255,.68)}
.user-dropdown{display:none;position:absolute;right:0;top:calc(100% + 10px);width:270px;overflow:hidden;background:#fff;color:var(--text);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow-md)}
.user-dropdown.open{display:block}
.dd-head{padding:15px 16px;background:var(--tint);border-bottom:1px solid var(--line)}
.dd-head b{display:block;font-size:14.5px;overflow-wrap:anywhere}
.dd-head small{display:block;margin:1px 0 9px;font-size:12.5px;color:var(--faint);overflow-wrap:anywhere}
.user-dropdown a{display:flex;align-items:center;gap:12px;padding:12px 16px;color:var(--text);font-size:14px;font-weight:500;text-decoration:none}
.user-dropdown a .ic{color:var(--faint)}
.user-dropdown a:hover{background:var(--tint)}
.user-dropdown a.dd-danger,.user-dropdown a.dd-danger .ic{color:var(--danger-dark)}
.user-dropdown a.dd-danger:hover{background:var(--danger-bg)}
/* ---- layout ---- */
.layout{display:flex;align-items:flex-start;min-height:calc(100vh - var(--topbar))}
.sidebar{position:sticky;top:var(--topbar);flex:0 0 var(--side);width:var(--side);height:calc(100vh - var(--topbar));overflow-y:auto;display:flex;flex-direction:column;padding:14px 12px;background:#fff;border-right:1px solid var(--line)}
.nav-title{padding:18px 12px 6px;font-size:11px;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--faint)}
.nav-title:first-child{padding-top:6px}
.nav-link{position:relative;display:flex;align-items:center;gap:12px;margin-bottom:2px;padding:10px 12px;border-radius:10px;color:var(--soft);font-size:14.5px;font-weight:500;text-decoration:none;transition:background .15s,color .15s}
.nav-link .ic{width:19px;height:19px;color:var(--faint);transition:color .15s}
.nav-link:hover{background:#F1F5F9;color:var(--text)}
.nav-link:hover .ic{color:var(--soft)}
.nav-link.active{background:var(--brand-50);color:var(--brand-dark);font-weight:600}
.nav-link.active .ic{color:var(--brand)}
.nav-link.active::before{content:'';position:absolute;left:-12px;top:9px;bottom:9px;width:3px;border-radius:0 3px 3px 0;background:var(--brand)}
.side-foot{margin-top:auto;padding:16px 12px 2px;border-top:1px solid var(--line);font-size:12px;line-height:1.45;color:var(--faint)}
.side-foot b{display:block;font-weight:600;color:var(--soft)}
.scrim{display:none}
.main-content{flex:1;min-width:0;padding:30px 36px 56px;transition:opacity .15s}
.main-content.loading{opacity:.5;pointer-events:none}
.busy-line{display:none;position:fixed;left:0;right:0;top:var(--topbar);height:3px;z-index:65;overflow:hidden;background:var(--brand-100)}
.busy-line::before{content:'';display:block;width:35%;height:100%;background:var(--brand);animation:slide 1s ease-in-out infinite}
body.busy .busy-line{display:block}
@keyframes slide{0%{margin-left:-35%}100%{margin-left:100%}}
.page{max-width:1120px}
.page-narrow{max-width:720px}
.page-head{display:flex;align-items:center;flex-wrap:wrap;gap:14px;margin-bottom:24px}
.page-icon{flex:none;width:46px;height:46px;border-radius:13px;display:grid;place-items:center;background:var(--brand-50);color:var(--brand);box-shadow:inset 0 0 0 1px var(--brand-100)}
.page-icon .ic{width:23px;height:23px}
.page-title{flex:1 1 220px;min-width:0}
.page-title h1{font-size:23px;line-height:1.2;font-weight:700;letter-spacing:-.3px;color:var(--ink)}
.page-title p{margin-top:3px;font-size:14px;color:var(--soft)}
.head-actions{display:flex;flex-wrap:wrap;gap:10px}
/* ---- cards ---- */
.card{margin-bottom:20px;padding:24px;background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow-sm)}
.card-flush{padding:0;overflow:hidden}
.card-head{display:flex;align-items:center;flex-wrap:wrap;gap:12px;padding:16px 20px;border-bottom:1px solid var(--line)}
.card-head h2,.section-h{font-size:15px;font-weight:700;color:var(--ink)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:20px;margin-bottom:20px}
.grid>.card{margin-bottom:0}
.stat{display:flex;flex-direction:column;gap:16px}
.stat-head{display:flex;align-items:center;gap:13px}
.stat-icon{flex:none;width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:var(--brand-50);color:var(--brand)}
.stat-icon.warn{background:var(--warn-bg);color:var(--warn)}
.stat-icon .ic{width:21px;height:21px}
.stat-title{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
.stat-sub{font-size:14px;color:var(--soft)}
.meta{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:14px}
.meta-k{color:var(--faint)}
.meta-v{font-weight:600;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:9px;padding:6px 15px 6px 12px;border-radius:999px;font-size:14px;font-weight:600}
.pill .dot{width:9px;height:9px;border-radius:50%;background:currentColor}
.pill-on{background:var(--ok-bg);color:var(--ok-ink)}
.pill-on .dot{background:var(--ok);box-shadow:0 0 0 4px rgba(22,163,74,.2)}
.pill-wait{background:var(--warn-bg);color:var(--warn-ink)}
.pill-wait .dot{background:var(--warn);box-shadow:0 0 0 4px rgba(234,88,12,.2);animation:pulse 1.2s ease-in-out infinite}
.pill-off{background:#F1F5F9;color:var(--soft)}
.pill-off .dot{background:#94A3B8}
@keyframes pulse{50%{opacity:.35}}
.motion-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.mot{display:flex;flex-direction:column;align-items:center;gap:6px;padding:13px 4px;border:1px solid var(--line);border-radius:12px;background:var(--tint);color:var(--faint);font-size:12px;font-weight:700;letter-spacing:.05em;transition:background .2s,color .2s,box-shadow .2s}
.mot .ic{width:22px;height:22px;opacity:.65}
.mot.on{background:var(--brand);border-color:var(--brand);color:#fff;box-shadow:0 4px 14px rgba(21,101,192,.38)}
.mot.on .ic{opacity:1}
.mot-estop{grid-column:1/-1;flex-direction:row;justify-content:center;gap:10px;padding:13px 8px}
.mot-estop span::after{content:'\2002\00b7\2002 Clear';font-weight:600;letter-spacing:0}
.mot-estop.on span::after{content:'\2002\00b7\2002 ACTIVE'}
.mot-estop.on{background:var(--danger);border-color:var(--danger);box-shadow:0 4px 14px rgba(220,38,38,.42)}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:20px 28px;margin-top:16px}
.kv dt{margin-bottom:3px;font-size:11.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:var(--faint)}
.kv dd{font-size:14.5px;font-weight:600;color:var(--ink);overflow-wrap:anywhere}
.clock{margin-top:8px;font-size:36px;line-height:1.15;font-weight:700;letter-spacing:-.5px;color:var(--ink);font-variant-numeric:tabular-nums}
.clock-date{margin-top:4px;font-size:15px;color:var(--soft);font-variant-numeric:tabular-nums}
/* ---- tables ---- */
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse}
thead th{padding:11px 20px;background:var(--tint);border-bottom:1px solid var(--line);font-size:11.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;text-align:left;white-space:nowrap;color:var(--faint)}
tbody td{padding:14px 20px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#FAFCFF}
th.col-actions,td.col-actions{text-align:right}
.actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px}
.actions form{display:contents}
.cell-user{display:flex;align-items:center;gap:12px;min-width:0}
.cell-user .avatar{width:38px;height:38px;font-size:14.5px}
.cell-user>div{min-width:0}
.cell-user b{display:block;font-weight:600;color:var(--ink);overflow-wrap:anywhere}
.cell-user small{display:block;font-size:12.5px;color:var(--faint);overflow-wrap:anywhere}
.file-name{display:inline-flex;align-items:center;gap:10px;font-weight:600;color:var(--ink);text-decoration:none;overflow-wrap:anywhere}
a.file-name:hover{color:var(--brand)}
.file-name .ic{color:var(--brand)}
.pin{display:inline-block;padding:5px 12px;border-radius:8px;background:var(--brand-50);color:var(--brand-dark);font-family:var(--mono);font-size:13.5px;font-weight:700}
.mono{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.sub{display:block;margin-top:3px;font-size:12.5px;color:var(--faint)}
.nw{white-space:nowrap}
td.empty{padding:38px 20px;text-align:center;color:var(--faint)}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:999px;background:#F1F5F9;color:var(--soft);font-size:12.5px;font-weight:600;white-space:nowrap}
.badge .ic{width:13px;height:13px}
.badge-blue{background:var(--brand-50);color:var(--brand-dark)}
.badge-violet{background:#F3E8FF;color:#6B21A8}
.badge-warn{background:var(--warn-bg);color:var(--warn-ink)}
.badge-ok{background:var(--ok-bg);color:var(--ok-ink)}
/* ---- buttons ---- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:42px;padding:8px 18px;border:1px solid transparent;border-radius:10px;background:none;font-size:14px;font-weight:600;line-height:1.2;text-decoration:none;white-space:nowrap;transition:background .15s,border-color .15s,box-shadow .15s,color .15s}
.btn .ic{width:17px;height:17px;vertical-align:0}
.btn-sm{min-height:34px;padding:6px 12px;font-size:13px;border-radius:9px}
.btn-sm .ic{width:15px;height:15px}
.btn-block{width:100%}
.btn-primary{background:var(--brand);color:#fff;box-shadow:0 1px 2px rgba(11,61,145,.32)}
.btn-primary:hover{background:var(--brand-dark);box-shadow:0 4px 12px rgba(11,61,145,.3)}
.btn-outline{background:#fff;color:var(--brand-dark);border-color:var(--line-2)}
.btn-outline:hover{background:var(--brand-50);border-color:var(--brand)}
.btn-cancel{background:#fff;color:var(--soft);border-color:var(--line-2)}
.btn-cancel:hover{background:var(--tint);color:var(--text)}
.btn-danger{background:var(--danger);color:#fff;box-shadow:0 1px 2px rgba(185,28,28,.32)}
.btn-danger:hover{background:var(--danger-dark);box-shadow:0 4px 12px rgba(185,28,28,.3)}
.btn-danger-outline{background:#fff;color:var(--danger-dark);border-color:var(--danger-line)}
.btn-danger-outline:hover{background:var(--danger-bg);border-color:var(--danger)}
.btn:disabled{opacity:.55;cursor:not-allowed;box-shadow:none}
/* ---- forms ---- */
.form-group{margin-bottom:18px}
.form-group>label,.field-label{display:block;margin-bottom:6px;font-size:13px;font-weight:600;color:var(--text)}
input:not([type=checkbox]):not([type=radio]):not([type=file]):not([type=hidden]),select,textarea{display:block;width:100%;min-height:42px;padding:9px 12px;border:1px solid var(--line-2);border-radius:10px;background:#fff;font-size:var(--fs-input);line-height:1.4;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(21,101,192,.16)}
input::placeholder,textarea::placeholder{color:#94A3B8}
input:disabled,input[readonly],select:disabled,textarea[readonly]{background:#F1F5F9;color:var(--faint)}
select{-webkit-appearance:none;appearance:none;padding-right:38px;cursor:pointer;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748B' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;background-size:16px}
input[type=file]{display:block;width:100%;padding:9px;border:1px dashed var(--line-2);border-radius:10px;background:var(--tint);font-size:14px;cursor:pointer}
input[type=file]::file-selector-button{margin-right:12px;padding:8px 15px;border:0;border-radius:8px;background:var(--brand);color:#fff;font-weight:600;cursor:pointer}
input[type=file]::-webkit-file-upload-button{margin-right:12px;padding:8px 15px;border:0;border-radius:8px;background:var(--brand);color:#fff;font-weight:600;cursor:pointer}
input[type=checkbox],input[type=radio]{flex:none;width:18px;height:18px;margin-top:2px;accent-color:var(--brand)}
.form-group>label.check{display:flex;align-items:flex-start;gap:10px;margin-bottom:0;font-size:14px;font-weight:400;cursor:pointer}
.form-group>label .opt{font-weight:400;color:var(--faint)}
.card>.section-h{margin-bottom:14px}
#ota-status:not(:empty){margin-top:18px}
textarea.code{min-height:320px;font-family:var(--mono);font-size:13px;line-height:1.55;white-space:pre;overflow:auto;resize:vertical}
.form-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 18px}
.form-hint{margin-top:6px;font-size:12.5px;color:var(--faint)}
.form-section{margin-top:8px;padding-top:20px;border-top:1px solid var(--line)}
.form-section h3{margin-bottom:14px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
.form-actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:26px;padding-top:22px;border-top:1px solid var(--line)}
.form-actions.bare{margin-top:0;padding-top:0;border-top:0}
.inline-form{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px}
.inline-form .form-group{flex:1 1 220px;min-width:0;margin-bottom:0}
.pw{position:relative}
.pw input{padding-right:46px!important}
.pw-toggle{position:absolute;top:50%;right:5px;width:34px;height:34px;margin-top:-17px;display:grid;place-items:center;border:0;border-radius:8px;background:none;color:var(--faint)}
.pw-toggle:hover{background:#F1F5F9;color:var(--text)}
.pw-toggle .ic-eye-off,.pw-toggle.on .ic-eye{display:none}
.pw-toggle.on .ic-eye-off{display:inline-block}
.progress{height:6px;margin-top:16px;overflow:hidden;border-radius:999px;background:var(--brand-100)}
.progress i{display:block;width:35%;height:100%;border-radius:999px;background:var(--brand);animation:slide 1.1s ease-in-out infinite}
.crumbs{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:18px}
/* ---- alerts & state cards ---- */
.alert{display:flex;align-items:flex-start;gap:11px;margin-bottom:18px;padding:13px 15px;border:1px solid transparent;border-radius:12px;font-size:14px;line-height:1.5}
.alert .ic{margin-top:2px}
.alert>div{min-width:0;overflow-wrap:anywhere}
.alert-info{background:var(--brand-50);border-color:var(--brand-200);color:var(--brand-ink)}
.alert-success{background:var(--ok-bg);border-color:var(--ok-line);color:var(--ok-ink)}
.alert-warn{background:var(--warn-bg);border-color:var(--warn-line);color:var(--warn-ink)}
.alert-danger{background:var(--danger-bg);border-color:var(--danger-line);color:var(--danger-ink)}
.state{max-width:520px;margin:5vh auto 0;padding:38px 30px;text-align:center}
.state-icon{width:66px;height:66px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center}
.state-icon .ic{width:30px;height:30px}
.state-icon.danger{background:var(--danger-bg);color:var(--danger)}
.state-icon.ok{background:var(--ok-bg);color:var(--ok)}
.state-icon.info{background:var(--brand-50);color:var(--brand)}
.state h2{margin-bottom:8px;font-size:20px;font-weight:700;color:var(--ink)}
.state p{font-size:14.5px;color:var(--soft);overflow-wrap:anywhere}
.state p b{color:var(--ink)}
.state-note{margin-top:6px;font-size:13px!important;color:var(--faint)!important}
.state-actions{display:flex;flex-wrap:wrap;justify-content:center;gap:10px;margin-top:26px}
.state-actions .progress{flex:1 1 100%;margin-top:0}
.account-id{margin-bottom:22px;padding-bottom:20px;border-bottom:1px solid var(--line)}
/* ---- sign-in ---- */
.auth{min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:radial-gradient(900px 520px at 15% -10%,#1F5FBF 0%,transparent 62%),radial-gradient(800px 480px at 105% 110%,#0F4DA6 0%,transparent 58%),linear-gradient(160deg,#0B2447,#0F2E5C)}
.auth-card{width:100%;max-width:420px;padding:38px 34px 30px;background:#fff;border-radius:20px;box-shadow:var(--shadow-lg)}
.auth-brand{margin-bottom:26px;text-align:center}
.auth-logo{display:block;width:84px;height:84px;margin:0 auto 14px;filter:drop-shadow(0 8px 16px rgba(15,46,92,.3))}
.auth-brand h1{font-size:21px;letter-spacing:.6px;color:var(--ink)}
.auth-brand p{margin-top:3px;font-size:13.5px;color:var(--faint)}
.auth-foot{margin-top:22px;text-align:center;font-size:12.5px;color:var(--faint)}
/* ---- focus ---- */
.btn:focus-visible{outline:3px solid rgba(21,101,192,.4);outline-offset:2px}
.nav-link:focus-visible{outline:3px solid rgba(21,101,192,.4);outline-offset:-2px}
.user-btn:focus-visible,.menu-btn:focus-visible{outline:3px solid rgba(255,255,255,.55);outline-offset:2px}
a:focus-visible,.pw-toggle:focus-visible{outline:3px solid rgba(21,101,192,.4);outline-offset:2px}
/* ---- responsive ---- */
@media(min-width:701px) and (max-width:1180px){
.actions .btn .lbl{display:none}
.actions .btn{padding:6px 10px}
}
@media(max-width:900px){
.menu-btn{display:inline-flex}
.sidebar{position:fixed;left:0;top:var(--topbar);bottom:0;z-index:60;height:auto;width:min(86vw,300px);flex:none;visibility:hidden;transform:translateX(-104%);transition:transform .25s ease,visibility 0s linear .25s}
body.nav-open .sidebar{visibility:visible;transform:none;box-shadow:var(--shadow-lg);transition:transform .25s ease}
.scrim{display:block;position:fixed;left:0;right:0;top:var(--topbar);bottom:0;z-index:55;background:rgba(15,23,42,.5);opacity:0;visibility:hidden;transition:opacity .2s ease,visibility 0s linear .2s}
body.nav-open .scrim{opacity:1;visibility:visible;transition:opacity .2s ease}
body.nav-open{overflow:hidden}
.main-content{padding:24px 22px 48px}
}
@media(max-width:700px){
.stack thead{display:none}
.stack,.stack tbody,.stack tr,.stack td{display:block;width:100%}
.stack tr{padding:14px 16px;border-bottom:1px solid var(--line)}
.stack tbody tr:last-child{border-bottom:0}
.stack tbody tr:hover{background:none}
.stack td{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:7px 0;border:0;text-align:right}
.stack td::before{content:attr(data-label);flex:0 0 36%;font-size:11.5px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;text-align:left;color:var(--faint)}
.stack td.cell-main{display:block;padding:0 0 8px;text-align:left}
.stack td.cell-main::before,.stack td.empty::before{display:none}
.stack td.col-actions{display:block;padding:10px 0 0}
.stack td.col-actions::before{display:none}
.stack .actions{justify-content:stretch}
.stack .actions .btn,.stack .actions form{flex:1 1 auto}
.stack .actions form .btn{width:100%}
.stack .actions .btn .lbl{display:inline}
.stack-form td{display:block;padding:6px 0;text-align:left}
.stack-form td::before{display:block;margin-bottom:5px}
.stack-pair tr{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:0 12px}
.stack-pair td.cell-main{grid-column:1/-1}
}
@media(max-width:640px){
:root{--topbar:56px;--fs-input:16px}
.topbar{gap:8px;padding:0 14px}
.brand-sub,.user-meta,.user-btn .ic-chev{display:none}
.brand-logo{width:36px;height:36px}
.user-btn{padding:0 5px}
.main-content{padding:20px 14px 40px}
.card{padding:18px 16px}
.card-head{padding:14px 16px}
.page-head{gap:12px;margin-bottom:20px}
.page-icon{width:40px;height:40px;border-radius:11px}
.page-icon .ic{width:20px;height:20px}
.page-title h1{font-size:20px}
.head-actions,.head-actions .btn{width:100%}
.form-row{grid-template-columns:1fr}
.form-actions .btn{flex:1 1 140px}
.btn{min-height:44px}
.btn-sm{min-height:40px}
.kv{grid-template-columns:1fr 1fr;gap:16px}
.clock{font-size:30px}
.state{margin-top:2vh;padding:30px 18px}
.auth-card{padding:30px 22px 24px}
}
@media(max-width:380px){.kv{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){*,::before,::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
)CSS";

#undef S_PATH
#undef S_POLY
#undef S_GON
#undef S_LINE
#undef S_CIRC
#undef S_RECT
#undef S_ELL
#undef SVG_ICON
#undef SVG_OPEN
#undef SVG_CLOSE

// Tags shared by every page's <head>: charset first (must be within the first
// 1024 bytes), the logo as the tab icon (declared explicitly so browsers don't
// probe /favicon.ico, which would cost the ESP32 a socket for a 404), and the
// stylesheet.
static const char HEAD_COMMON[] =
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1,viewport-fit=cover'>"
    "<meta name='theme-color' content='#0F2E5C'>"
    "<link rel='icon' type='image/png' href='/logo.png?v=" LOGO_VER "'>"
    "<link rel='stylesheet' href='/style.css?v=" CSS_VER "'>";

// Menu / sidebar-drawer / password-toggle helpers present on every page. Pages
// built by handleRoot() add their own tab-switching script on top of this.
static const char SHELL_JS[] = R"JS(
function toggleNav(f){var o=typeof f==='boolean'?f:!document.body.classList.contains('nav-open');
document.body.classList.toggle('nav-open',o);
var b=document.getElementById('menuBtn');if(b)b.setAttribute('aria-expanded',o?'true':'false');}
function closeUserMenu(){var d=document.getElementById('userDrop'),b=document.getElementById('userBtn');
if(d)d.classList.remove('open');if(b)b.setAttribute('aria-expanded','false');}
function toggleMenu(e){e.stopPropagation();var d=document.getElementById('userDrop'),b=document.getElementById('userBtn');
var o=!d.classList.contains('open');d.classList.toggle('open',o);b.setAttribute('aria-expanded',o?'true':'false');}
function togglePw(b){var i=b.parentNode.querySelector('input');var s=i.type==='password';
i.type=s?'text':'password';b.classList.toggle('on',s);b.setAttribute('aria-label',s?'Hide password':'Show password');}
document.addEventListener('click',closeUserMenu);
document.addEventListener('keydown',function(e){if(e.key==='Escape'){closeUserMenu();toggleNav(false);}});
)JS";

// ============================================================
//  Shared UI building blocks
// ============================================================
static String htmlEsc(const String &s)
{
  String o;
  o.reserve(s.length() + 8);
  for (unsigned i = 0; i < s.length(); i++)
  {
    char c = s[i];
    if (c == '&')
      o += "&amp;";
    else if (c == '<')
      o += "&lt;";
    else if (c == '>')
      o += "&gt;";
    else if (c == '"')
      o += "&quot;";
    else if (c == '\'')
      o += "&#39;";
    else
      o += c;
  }
  return o;
}

// Full web access: Super Admin and Admin.
static bool isManagerRole(const String &role)
{
  return role == "SuperAdmin" || role == "Admin";
}

static String roleLabel(const String &role)
{
  return role == "SuperAdmin" ? String("Super Admin") : role;
}

// First letter of a name for avatar circles (a whole UTF-8 sequence, upper-cased when ASCII).
static String initialOf(const String &s)
{
  if (s.length() == 0)
    return String("?");
  unsigned char c = (unsigned char)s[0];
  if (c < 0x80)
    return String((char)toupper(c));
  unsigned n = 1;
  while (n < s.length() && ((unsigned char)s[n] & 0xC0) == 0x80)
    n++;
  return s.substring(0, n);
}

// Name shown in the top bar: the BLE user's name, or the web admin's login.
static String currentDisplayName()
{
  String email = currentUserEmail();
  if (email.length() == 0)
    return String(webAdminUser);
  for (int i = 0; i < userCount; i++)
  {
    if (String(users[i].email).equalsIgnoreCase(email))
      return String(users[i].name);
  }
  return email;
}

static String topbarHtml()
{
  String rawName = currentDisplayName();
  String email = currentUserEmail();
  String role = currentRole();
  String h;
  h.reserve(1800);
  h = "<header class='topbar'>";
  h += "<button class='menu-btn' id='menuBtn' type='button' onclick='toggleNav()' aria-label='Menu' "
       "aria-controls='sidebar' aria-expanded='false'><i class='ic ic-menu'></i></button>";
  h += "<a class='brand' href='/'><img class='brand-logo' src='/logo.png?v=" LOGO_VER "' width='40' height='40' alt=''>"
       "<span class='brand-text'><span class='brand-name'>INTELLICONTROL</span>"
       "<span class='brand-sub'>PLC Control Panel</span></span></a>";
  h += "<span class='grow'></span>";
  h += "<div class='user-menu'>";
  h += "<button class='user-btn' id='userBtn' type='button' onclick='toggleMenu(event)' aria-haspopup='true' aria-expanded='false'>";
  h += "<span class='avatar'>" + htmlEsc(initialOf(rawName)) + "</span>";
  h += "<span class='user-meta'><b>" + htmlEsc(rawName) + "</b><small>" + roleLabel(role) + "</small></span>";
  h += "<i class='ic ic-chev'></i></button>";
  h += "<div class='user-dropdown' id='userDrop'>";
  h += "<div class='dd-head'><b>" + htmlEsc(rawName) + "</b>";
  h += "<small>" + (email.length() > 0 ? htmlEsc(email) : String("Web administrator")) + "</small>";
  h += "<span class='badge badge-violet'>" + roleLabel(role) + "</span></div>";
  h += "<a href='/account'><i class='ic ic-key'></i>Account settings</a>";
  h += "<a href='/logout' class='dd-danger'><i class='ic ic-logout'></i>Logout</a>";
  h += "</div></div></header>";
  h += "<div class='busy-line'></div>";
  return h;
}

static String navItem(const char *tab, const char *icon, const char *label, const String &active)
{
  bool on = active == tab;
  String h = "<a class='nav-link";
  if (on)
    h += " active";
  h += "' id='nav-";
  h += tab;
  h += "' data-tab='";
  h += tab;
  h += "' href='/?tab=";
  h += tab;
  h += "'";
  if (on)
    h += " aria-current='page'";
  h += "><i class='ic ic-";
  h += icon;
  h += "'></i><span>";
  h += label;
  h += "</span></a>";
  return h;
}

// Sidebar (a slide-in drawer on small screens) trimmed to what `role` may open.
// Items are plain links so they work on every page; handleRoot() upgrades them
// to in-page tab switches.
static String sidebarHtml(const String &role, const String &active)
{
  bool isAdmin = isManagerRole(role);
  bool isOperator = (role == "Operator");
  String h;
  h.reserve(2400);
  h = "<aside class='sidebar' id='sidebar'><nav aria-label='Main navigation'>";
  h += "<div class='nav-title'>Overview</div>";
  h += navItem("home", "home", "Home", active);
  if (isAdmin)
  {
    h += "<div class='nav-title'>Management</div>";
    h += navItem("users", "users", "User Management", active);
    h += navItem("devices", "phone", "Device Registry", active);
  }
  if (isAdmin || isOperator)
  {
    h += "<div class='nav-title'>Configuration</div>";
    h += navItem("outconfig", "sliders", "Output Config", active);
    h += navItem("inconfig", "cpu", "Input Config", active);
    h += navItem("network", "wifi", "Network Settings", active);
    h += navItem("time", "clock", "Time &amp; Date", active);
  }
  if (isAdmin)
  {
    h += "<div class='nav-title'>System</div>";
    h += navItem("ota", "cloud", "Firmware Update", active);
    if (cloudLinkAvailable())
      h += navItem("cloud", "wifi", "Cloud Link", active);
    h += navItem("firebase", "cloud", "Firebase", active);
    h += navItem("files", "folder", "Files", active);
  }
  h += "</nav><div class='side-foot'><b>IntelliControl</b>" FIRMWARE_VERSION "</div></aside>";
  h += "<div class='scrim' onclick='toggleNav(false)'></div>";
  return h;
}

// Page heading: icon chip, title, optional subtitle and right-aligned actions.
static String panelHead(const char *icon, const char *title, const String &sub = String(), const String &actions = String())
{
  String h = "<div class='page-head'><span class='page-icon'><i class='ic ic-";
  h += icon;
  h += "'></i></span><div class='page-title'><h1>";
  h += title;
  h += "</h1>";
  if (sub.length() > 0)
  {
    h += "<p>";
    h += sub;
    h += "</p>";
  }
  h += "</div>";
  if (actions.length() > 0)
  {
    h += "<div class='head-actions'>";
    h += actions;
    h += "</div>";
  }
  h += "</div>";
  return h;
}

// kind: "info" | "success" | "warn" | "danger"
static const char *alertIcon(const char *kind)
{
  if (strcmp(kind, "success") == 0)
    return "check-circle";
  if (strcmp(kind, "warn") == 0)
    return "alert";
  if (strcmp(kind, "danger") == 0)
    return "alert-circle";
  return "info";
}

static String alertHtml(const char *kind, const String &msg)
{
  String h = "<div class='alert alert-";
  h += kind;
  h += "'><i class='ic ic-";
  h += alertIcon(kind);
  h += "'></i><div>";
  h += msg;
  h += "</div></div>";
  return h;
}

static String backButton(const String &url, const char *label = "Back")
{
  return "<a href='" + url + "' class='btn btn-cancel'><i class='ic ic-left'></i>" + String(label) + "</a>";
}

// Centred message card for results, errors and confirmations.
// kind: "ok" | "danger" | "info" (colours the icon disc).
static String stateCard(const char *kind, const char *icon, const String &title, const String &body, const String &actions = String())
{
  String h = "<div class='card state'><div class='state-icon ";
  h += kind;
  h += "'><i class='ic ic-";
  h += icon;
  h += "'></i></div><h2>";
  h += title;
  h += "</h2><p>";
  h += body;
  h += "</p>";
  if (actions.length() > 0)
  {
    h += "<div class='state-actions'>";
    h += actions;
    h += "</div>";
  }
  h += "</div>";
  return h;
}

// Which sidebar entry a page belongs under, judged from the URL it links back to.
static String navTabFor(const char *url)
{
  String u(url);
  int t = u.indexOf("tab=");
  if (t >= 0)
  {
    String tab = u.substring(t + 4);
    int amp = tab.indexOf('&');
    return amp >= 0 ? tab.substring(0, amp) : tab;
  }
  if (u.startsWith("/add") || u.startsWith("/edit"))
    return String("users");
  return String("");
}

// Tab switching for the full dashboard page (added on top of SHELL_JS). A sidebar
// click fetches just that tab's markup (?frag=1) and swaps it into
// .main-content instead of reloading the page — see the long note in handleRoot().
static const char SHELL_TAB_JS[] = R"JS(
var __pollTimer=null,__navSeq=0;
function __stopTimers(){if(__pollTimer){clearInterval(__pollTimer);__pollTimer=null;}}
function __runScripts(c){var l=c.querySelectorAll('script');
for(var i=0;i<l.length;i++){var o=l[i],s=document.createElement('script');
if(o.src){s.src=o.src;}else{s.textContent=o.textContent;}o.parentNode.replaceChild(s,o);}}
function showTab(t,noPush){
var mc=document.querySelector('.main-content');
if(!mc){window.location='/?tab='+encodeURIComponent(t);return;}
var seq=++__navSeq;
document.body.classList.add('busy');mc.classList.add('loading');
fetch('/?tab='+encodeURIComponent(t)+'&frag=1',{cache:'no-store',headers:{'X-Requested-With':'fetch'}})
.then(function(r){if(!r.ok||(r.url&&r.url.indexOf('/login')!==-1))throw new Error('nav-failed');return r.text();})
.then(function(frag){
if(seq!==__navSeq)return;
__stopTimers();mc.innerHTML=frag;__runScripts(mc);
var items=document.querySelectorAll('.nav-link');
for(var i=0;i<items.length;i++){items[i].classList.remove('active');items[i].removeAttribute('aria-current');}
var n=document.getElementById('nav-'+t);
if(n){n.classList.add('active');n.setAttribute('aria-current','page');document.title=n.textContent.trim()+' | IntelliControl';}
if(!noPush)history.pushState({tab:t},'','/?tab='+encodeURIComponent(t));
__currentTab=t;window.scrollTo(0,0);
document.body.classList.remove('busy');mc.classList.remove('loading');})
.catch(function(){if(seq===__navSeq)window.location='/?tab='+encodeURIComponent(t);});}
document.addEventListener('click',function(e){
var a=e.target.closest?e.target.closest('a.nav-link[data-tab]'):null;
if(a&&e.button===0&&!e.metaKey&&!e.ctrlKey&&!e.shiftKey&&!e.altKey){
e.preventDefault();toggleNav(false);showTab(a.getAttribute('data-tab'));}});
window.addEventListener('popstate',function(){
var t=new URLSearchParams(window.location.search).get('tab')||'home';
if(t!==__currentTab)showTab(t,true);});
)JS";

// Home tab live updater. It travels with the panel's own markup so it works both
// on a full page load and when the panel is swapped in as an AJAX fragment.
static const char HOME_JS[] = R"JS(
function updateHomeUI(s){
var st=(s.ble_conn===1&&s.ble_auth===1)?'on':(s.ble_conn===1?'wait':'off');
var bc=document.getElementById('hble-conn'),bt=document.getElementById('hble-txt');
var bu=document.getElementById('hble-user'),bn=document.getElementById('hble-uname');
if(bc)bc.className='pill pill-'+st;
if(bt)bt.textContent=st==='on'?'Connected':(st==='wait'?'Authenticating...':'Not connected');
if(bu){bu.hidden=st!=='on';if(bn)bn.textContent=s.ble_user||'Unknown';}
var m={estop:s.estop,up:s.up,down:s.down,left:s.left,right:s.right};
for(var k in m){var el=document.getElementById('m-'+k);if(el)el.classList.toggle('on',m[k]===1);}
var sum=document.getElementById('hmot-sum');
if(sum)sum.textContent=(s.up||s.down||s.left||s.right)?'Motion active':'No active motion';}
if(typeof __stopTimers==='function')__stopTimers();
__pollTimer=setInterval(function(){
var __pc=new AbortController();
var __pt=setTimeout(function(){__pc.abort();},2500);
fetch('/motion/status',{cache:'no-store',signal:__pc.signal}).then(function(r){clearTimeout(__pt);return r.json();})
.then(function(s){updateHomeUI(s);}).catch(function(){clearTimeout(__pt);});
},3000);
)JS";

// Output Config save without a full page reload (the validation mirrors the
// server's). The pin count is spliced in between OC_JS_A and OC_JS_B.
static const char OC_JS_A[] = R"JS(
(function(){
var f=document.getElementById('oc-form');if(!f)return;
var b=document.getElementById('oc-save-btn');
var m=document.getElementById('oc-save-msg');
function setMsg(ok,msg){if(!m)return;m.hidden=false;m.className='alert '+(ok?'alert-success':'alert-danger');
m.innerHTML="<i class='ic ic-"+(ok?'check-circle':'alert-circle')+"'></i><div></div>";m.lastChild.textContent=msg;}
f.addEventListener('submit',function(e){e.preventDefault();
var functions=[],motions=[];
for(var p=0;p<)JS";
static const char OC_JS_B[] = R"JS(;p++){
var fsel=f.elements['pin_'+p+'_function'];if(fsel){functions.push(fsel.value);}
var msel=f.elements['pin_'+p+'_motion'];if(msel){motions.push(msel.value);}
}
var noneVal='0';
var funcSeen={};
for(var i=0;i<functions.length;i++){
if(funcSeen[functions[i]]){setMsg(false,'Save failed: each output must have a unique digital function.');return;}
funcSeen[functions[i]]=true;}
var motSeen={};
for(var i=0;i<motions.length;i++){
if(motions[i]!==noneVal){
if(motSeen[motions[i]]){setMsg(false,'Save failed: two outputs cannot be assigned the same motion.');return;}
motSeen[motions[i]]=true;}
}
if(b)b.disabled=true;
var body=new URLSearchParams(new FormData(f)).toString();
fetch('/outconfig',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch'},body:body})
.then(function(r){return r.json().then(function(j){return {ok:r.ok,body:j};});})
.then(function(x){
if(!x.ok||!x.body||!x.body.ok)throw new Error((x.body&&x.body.msg)?x.body.msg:'Save failed. Please try again.');
setMsg(true,'Configuration saved successfully.');
})
.catch(function(err){setMsg(false,(err&&err.message)?err.message:'Save failed. Please try again.');})
.finally(function(){if(b)b.disabled=false;});
});
})();
)JS";

// ---- table / dashboard fragments ----

// "Perpetual" badge, or a "Timed" badge with its date range underneath.
static String accessCell(const User &u)
{
  if (u.accessType != ACCESS_TIMED)
    return String("<span class='badge'>Perpetual</span>");
  return "<div><span class='badge badge-warn'><i class='ic ic-clock'></i>Timed</span><span class='sub'>"
         "<span class='nw'>" +
         formatDateTime(u.startTs) + "</span> to <span class='nw'>" + formatDateTime(u.endTs) +
         "</span></span></div>";
}

static String roleBadge(const char *role)
{
  bool admin = strcmp(role, "Admin") == 0;
  return String("<span class='badge ") + (admin ? "badge-violet" : "badge-blue") + "'>" + htmlEsc(String(role)) + "</span>";
}

// One live indicator in the Home tab's motion panel.
static String motionChip(const char *id, const char *icon, const char *label, bool on)
{
  String h = "<div id='m-";
  h += id;
  h += "' class='mot mot-";
  h += id;
  if (on)
    h += " on";
  h += "'><i class='ic ic-";
  h += icon;
  h += "'></i><span>";
  h += label;
  h += "</span></div>";
  return h;
}

static String kvItem(const char *label, const String &valueHtml)
{
  return "<div><dt>" + String(label) + "</dt><dd>" + valueHtml + "</dd></div>";
}

// Icon + label button for table action columns (the label hides on mid-width
// screens, so the tooltip / aria-label carries the meaning there).
static String actionLink(const String &href, const char *cls, const char *icon, const char *label, const char *tip)
{
  return "<a href='" + href + "' class='btn btn-sm " + cls + "' title='" + tip + "' aria-label='" + tip +
         "'><i class='ic ic-" + icon + "'></i><span class='lbl'>" + label + "</span></a>";
}

// Access Type dropdown + From/To date-time inputs (shown only for Timed).
// `u` is null on the Add form (defaults to Perpetual).
static String accessFormFields(const User *u)
{
  bool timed = u && u->accessType == ACCESS_TIMED;
  String h = "<div class='form-section'><h3>Access</h3>";
  h += "<div class='form-group'><label for='accessType'>Access type</label>";
  h += "<select name='accessType' id='accessType' "
       "onchange=\"var t=this.value==='timed';document.getElementById('timedBox').hidden=!t;"
       "document.getElementById('fromTime').required=document.getElementById('toTime').required=t;\">";
  h += "<option value='perpetual'" + String(timed ? "" : " selected") + ">Perpetual (any time)</option>";
  h += "<option value='timed'" + String(timed ? " selected" : "") + ">Timed (only between a start and end date/time)</option>";
  h += "</select><div class='form-hint'>Timed users can sign in only between the start and end below.</div></div>";
  h += "<div class='form-row' id='timedBox'" + String(timed ? "" : " hidden") + ">";
  h += "<div class='form-group'><label for='fromTime'>From (date &amp; time)</label>"
       "<input type='datetime-local' name='fromTime' id='fromTime' value='" +
       (timed ? formatDateTime(u->startTs, true) : String("")) + "'" + (timed ? " required" : "") + "></div>";
  h += "<div class='form-group'><label for='toTime'>To (date &amp; time)</label>"
       "<input type='datetime-local' name='toTime' id='toTime' value='" +
       (timed ? formatDateTime(u->endTs, true) : String("")) + "'" + (timed ? " required" : "") + "></div>";
  h += "</div></div>";
  return h;
}

// Password input with a show/hide eye button.
static String passwordField(const char *id, const char *name, const char *placeholder, const String &value = String(),
                            const char *extraAttrs = "")
{
  String h = "<div class='pw'><input id='";
  h += id;
  h += "' type='password' name='";
  h += name;
  h += "' placeholder='";
  h += placeholder;
  h += "'";
  if (value.length() > 0)
    h += " value='" + value + "'";
  h += " ";
  h += extraAttrs;
  h += "><button type='button' class='pw-toggle' onclick='togglePw(this)' aria-label='Show password'>"
       "<i class='ic ic-eye'></i><i class='ic ic-eye-off'></i></button></div>";
  return h;
}

// Focused confirmation card for deleting something (user or file).
static String confirmDeleteCard(const char *action, const char *hiddenName, const String &hiddenValueEsc,
                                const String &itemEsc, const String &cancelUrl, const char *noun)
{
  String h = "<form method='POST' action='";
  h += action;
  h += "' class='card state'><input type='hidden' name='";
  h += hiddenName;
  h += "' value='" + hiddenValueEsc + "'>";
  h += "<div class='state-icon danger'><i class='ic ic-trash'></i></div>";
  h += "<h2>Delete this ";
  h += noun;
  h += "?</h2><p>You are about to delete<br><b>" + itemEsc + "</b></p>";
  h += "<p class='state-note'>This action cannot be undone.</p>";
  h += "<div class='state-actions'><button type='submit' class='btn btn-danger'><i class='ic ic-trash'></i>Yes, delete</button>";
  h += backButton(cancelUrl, "Cancel") + "</div></form>";
  return h;
}

// ============================================================
//  Login page
// ============================================================
static String loginPage(const String &errMsg)
{
  String html;
  html.reserve(3200);
  html = "<!DOCTYPE html><html lang='en'><head>";
  html += HEAD_COMMON;
  html += "<title>Sign In | INTELLIControl</title></head><body>";
  html += "<main class='auth'><div class='auth-card'>";
  html += "<div class='auth-brand'><img class='auth-logo' src='/logo.png?v=" LOGO_VER "' width='84' height='84' alt=''>";
  html += "<h1>INTELLICONTROL</h1><p>PLC Control Panel</p></div>";
  if (errMsg.length() > 0)
    html += alertHtml("danger", errMsg);
  html += "<form method='POST' action='/login'>";
  html += "<div class='form-group'><label for='login-user'>Email address</label>";
  html += "<input id='login-user' type='email' name='username' placeholder='Enter your email address' "
          "autocomplete='username' required autofocus></div>";
  html += "<div class='form-group'><label for='login-pass'>Password</label>";
  html += passwordField("login-pass", "password", "Enter password", String(), "autocomplete='current-password' required");
  html += "</div>";
  html += "<button type='submit' class='btn btn-primary btn-block'><i class='ic ic-login'></i>Sign in</button>";
  html += "</form>";
  html += "<p class='auth-foot'>Authorised personnel only</p>";
  html += "</div></main><script>";
  html += SHELL_JS;
  html += "</script></body></html>";
  return html;
}

// ============================================================
//  Page helpers
// ============================================================
// Opens a standalone page (add / edit / confirm / account ...) in the same app
// shell as the dashboard: top bar, sidebar, then `.page`. `navTab` is the
// sidebar entry to highlight; the page heading is drawn only when `icon` is set.
// Close it with pageFoot().
static String pageHead(const char *title, const char *subtitle = nullptr, const char *navTab = nullptr,
                       const char *icon = nullptr, bool narrow = true)
{
  String h;
  h.reserve(5200);
  h = "<!DOCTYPE html><html lang='en'><head>";
  h += HEAD_COMMON;
  h += "<title>";
  h += title;
  h += " | IntelliControl</title></head><body>";
  h += topbarHtml();
  h += "<div class='layout'>";
  h += sidebarHtml(currentRole(), navTab ? String(navTab) : String());
  h += "<main class='main-content'><div class='page";
  if (narrow)
    h += " page-narrow";
  h += "'>";
  if (icon)
    h += panelHead(icon, title, subtitle ? String(subtitle) : String());
  return h;
}

static String pageFoot()
{
  String h = "</div></main></div><script>";
  h += SHELL_JS;
  h += "</script></body></html>";
  return h;
}

static String errorPage(String msg, const char *backUrl)
{
  String h = pageHead("Error", nullptr, navTabFor(backUrl).c_str());
  h += stateCard("danger", "alert-circle", "Something went wrong", msg, backButton(String(backUrl)));
  h += pageFoot();
  return h;
}

// ============================================================
//  Auth — cookie session
// ============================================================
static bool webAuth()
{
  int si = findSessionIdx();
  if (si >= 0)
  {
    // A timed user's session ends the moment their access window closes.
    // Web admin (no userEmail) and admin "Login As" sessions are exempt.
    if (sessions[si].userEmail.length() > 0 && !sessions[si].timeExempt)
    {
      int ui = findUserIndexByEmail(sessions[si].userEmail.c_str());
      if (ui >= 0 && !isUserAccessAllowed(users[ui]))
      {
        sessions[si].token = "";
        sessions[si].role = "";
        sessions[si].userEmail = "";
        Serial.printf("Web: access window ended — session closed for %s\n", users[ui].email);
        webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
        webServer.sendHeader("Location", "/login?timeout=1");
        sendSafe(302);
        return false;
      }
    }
    return true;
  }
  webServer.sendHeader("Location", "/login");
  sendSafe(302);
  return false;
}

// Accepts Admin or Operator for Output Config
static bool webAuthOutputConfig()
{
  if (!webAuth())
    return false;
  String role = currentRole();
  if (role != "SuperAdmin" && role != "Admin" && role != "Operator")
  {
    sendSafe(403, "text/html", errorPage("Access denied. Operator or Admin privileges required.", "/"));
    return false;
  }
  return true;
}

static bool webAuthAdmin()
{
  if (!webAuth())
    return false;
  if (!isManagerRole(currentRole()))
  {
    sendSafe(403, "text/html", errorPage("Access denied. Admin privileges required.", "/"));
    return false;
  }
  return true;
}

// Only the Super Admin may create, edit, delete or impersonate Admin accounts;
// an Admin may only manage Operators. Sends a 403 and returns false otherwise.
static bool webCanManageUser(int idx)
{
  if (currentRole() == "SuperAdmin" || String(users[idx].role) != "Admin")
    return true;
  sendSafe(403, "text/html", errorPage("Access denied. Only the Super Admin can manage Admin accounts.", "/?tab=users"));
  return false;
}

// ============================================================
//  Login / Logout
// ============================================================
static void handleLoginGet()
{
  if (findSessionIdx() >= 0)
  {
    webServer.sendHeader("Location", "/");
    sendSafe(302);
    return;
  }
  sendSafe(200, "text/html", loginPage(webServer.hasArg("timeout") ? "Your access time has ended. You have been logged out." : ""));
}

static void handleLoginPost()
{
  String username = webServer.arg("username");
  String password = webServer.arg("password");
  // Web admin credentials
  if (String(webAdminUser).equalsIgnoreCase(username) && password == webAdminPass)
  {
    int _slot = allocSessionSlot();
    sessions[_slot].token = generateToken();
    sessions[_slot].role = "SuperAdmin";
    sessions[_slot].userEmail = "";
    sessions[_slot].timeExempt = false;
    webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot].token + "; HttpOnly; Path=/");
    webServer.sendHeader("Location", "/");
    sendSafe(303);
    return;
  }
  // BLE user credentials — match by email only
  for (int i = 0; i < userCount; i++)
  {
    bool emailMatch = String(users[i].email).equalsIgnoreCase(username);
    if (emailMatch && String(users[i].password) == password)
    {
      if (!isUserAccessAllowed(users[i]))
      {
        String msg = (currentTimestamp() == "N/A")
                         ? String("Access not allowed: the device clock is unavailable, so your access time cannot be verified.")
                         : "Access not allowed at this time. Your access period is " + formatDateTime(users[i].startTs) +
                               " to " + formatDateTime(users[i].endTs) + ".";
        sendSafe(403, "text/html", loginPage(msg));
        return;
      }
      int _slot = allocSessionSlot();
      sessions[_slot].token = generateToken();
      sessions[_slot].role = String(users[i].role);
      sessions[_slot].userEmail = String(users[i].email);
      sessions[_slot].timeExempt = false;
      webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot].token + "; HttpOnly; Path=/");
      webServer.sendHeader("Location", "/");
      sendSafe(303);
      return;
    }
  }
  sendSafe(401, "text/html", loginPage("Invalid email address or password."));
}

static void handleLogout()
{
  int _si = findSessionIdx();
  if (_si >= 0)
  {
    sessions[_si].token = "";
    sessions[_si].role = "";
    sessions[_si].userEmail = "";
  }
  webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
  webServer.sendHeader("Location", "/login");
  sendSafe(303);
}

// ============================================================
//  SD card file helpers (Files tab)
// ============================================================
// Files up to this size can be edited in the browser. The limit is small on
// purpose: saving posts the whole text as a urlencoded form body, which this
// WebServer library copies several times over in RAM (raw body, a parsed
// copy and the decoded value), and the ESP32 has little free heap.
#define FILE_EDIT_MAX_BYTES 4096
// A larger file is shown read-only: only its last FILE_VIEW_MAX_BYTES bytes.
#define FILE_VIEW_MAX_BYTES 16384
// Lines are only counted for files up to this size, so listing the card
// can't stall the main loop (which also runs the safety I/O) on huge files.
#define FILE_COUNT_MAX_BYTES 262144UL

static String urlEnc(const String &s)
{
  String o;
  char buf[4];
  for (unsigned i = 0; i < s.length(); i++)
  {
    char c = s[i];
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~')
      o += c;
    else
    {
      snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
      o += buf;
    }
  }
  return o;
}

// A plain file name in the SD root: no path separators or characters FAT
// forbids, and not hidden/relative (leading dot). Blocks "../" tricks.
static bool validSdName(const String &n)
{
  if (n.length() == 0 || n.length() > 60 || n[0] == '.')
    return false;
  for (unsigned i = 0; i < n.length(); i++)
  {
    char c = n[i];
    if ((unsigned char)c < 0x20 || strchr("/\\:*?\"<>|", c))
      return false;
  }
  return true;
}

// A file in the SD root ("name") or inside a month folder ("YYYY-MM/name").
// The event logs live in month folders; nothing deeper is allowed.
static bool validSdPath(const String &n)
{
  int sl = n.indexOf('/');
  if (sl < 0)
    return validSdName(n);
  return validMonthStr(n.substring(0, sl)) && n.indexOf('/', sl + 1) < 0 && validSdName(n.substring(sl + 1));
}

// Files-tab URL that shows the folder holding `name` ("YYYY-MM/x.log" -> that
// month's folder; a root file -> the root listing).
static String filesTabUrl(const String &name)
{
  int sl = name.indexOf('/');
  return (sl > 0) ? "/?tab=files&dir=" + name.substring(0, sl) : String("/?tab=files");
}

// SD.open() throws std::bad_alloc when heap is low (see logEvent()); a failed
// open must degrade to "can't open", never abort the controller.
static bool sdOpen(const String &path, const char *mode, File &f)
{
  if (!sdOk) // a dead card costs loop() ~1.5 s per attempt: see logEvent()
    return false;
  try
  {
    f = SD.open(path, mode);
  }
  catch (...)
  {
    return false;
  }
  if (!f)
    sdCheckAfterFailedOpen();
  return (bool)f;
}

static String formatSize(uint32_t bytes)
{
  char buf[16];
  if (bytes < 1024)
    snprintf(buf, sizeof(buf), "%u B", (unsigned)bytes);
  else if (bytes < 1024UL * 1024UL)
    snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
  else
    snprintf(buf, sizeof(buf), "%.2f MB", bytes / (1024.0 * 1024.0));
  return String(buf);
}

// Number of lines (log entries) in an open file, or -1 if the file is too
// large or counting ran past `deadlineMs`.
static long countEntries(File &f, unsigned long deadlineMs)
{
  if (f.size() > FILE_COUNT_MAX_BYTES)
    return -1;
  uint8_t buf[256];
  long lines = 0;
  uint8_t last = '\n';
  int n;
  while ((n = f.read(buf, sizeof(buf))) > 0)
  {
    for (int i = 0; i < n; i++)
      if (buf[i] == '\n')
        lines++;
    last = buf[n - 1];
    if (millis() > deadlineMs)
      return -1;
  }
  if (last != '\n')
    lines++; // final line without a trailing newline
  return lines;
}

// ============================================================
//  Dashboard  —  two-column layout
// ============================================================
static void handleRoot()
{
  if (!webAuth())
    return;

  String role = currentRole();
  bool isAdmin = isManagerRole(role); // Super Admin or Admin: full web access
  bool isSuper = (role == "SuperAdmin");
  bool isOperator = (role == "Operator");
  String defaultTab = "home";
  String activeTab = webServer.hasArg("tab") ? webServer.arg("tab") : defaultTab;
  if (!isAdmin && activeTab == "users")
    activeTab = "home";
  if (!isAdmin && activeTab == "devices")
    activeTab = "home";
  if (!isAdmin && activeTab == "ota")
    activeTab = "home";
  if (!isAdmin && activeTab == "files")
    activeTab = "home";
  if ((!isAdmin || !cloudLinkAvailable()) && activeTab == "cloud")
    activeTab = "home";
  if (!isAdmin && activeTab == "firebase")
    activeTab = "home";
  if (activeTab != "home" && activeTab != "users" && activeTab != "outconfig" && activeTab != "network" && activeTab != "devices" && activeTab != "inconfig" && activeTab != "time" && activeTab != "ota" && activeTab != "files" && activeTab != "cloud" && activeTab != "firebase")
    activeTab = defaultTab;
  bool isHome = (activeTab == "home");
  bool isUsers = (activeTab == "users");
  bool isDevices = (activeTab == "devices");
  bool isOutConfig = (activeTab == "outconfig");
  bool isNetwork = (activeTab == "network");
  bool isInConfig = (activeTab == "inconfig");
  bool isTime = (activeTab == "time");
  bool isOta = (activeTab == "ota");
  bool isFiles = (activeTab == "files");
  bool isCloud = (activeTab == "cloud");
  bool isFirebase = (activeTab == "firebase");

  // fragMode: an AJAX tab-switch request (see showTab() in the page shell
  // script below) asking only for the active tab's own markup, not the
  // whole page shell. Every full page navigation opens a brand-new TCP
  // connection on this WebServer library (it never reuses connections —
  // "Connection: close" is sent unconditionally), and the ESP32's socket
  // table is small enough that browsing through several tabs in a normal
  // session can exhaust it, wedging the whole web server until a manual
  // reset. Serving tab switches as a small fragment swapped into the
  // existing page — instead of a full page reload — avoids opening a new
  // connection for every sidebar click.
  bool fragMode = webServer.hasArg("frag");

  // Start chunked response immediately so the browser doesn't time out while
  // we build the large HTML string.
  webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
  sendSafe(200, "text/html", "");

  // Helper lambda: flush html to client whenever it exceeds 4 KB,
  // then clear the buffer.
  //
  // A client that's actually gone — not just "closed the tab" (a clean
  // FIN, which connected()'s cheap probe below catches), but silently
  // vanished (WiFi range lost, app killed, a bad moment of BLE/WiFi
  // coexistence contention on this same radio) — leaves the ESP32's TCP
  // stack still believing the socket is open, because no FIN/RST ever
  // arrived to tell it otherwise. Writing to a socket like that runs into
  // WiFiClient::write()'s own internal retry loop: up to 10 attempts,
  // each waiting up to 1s for the socket to become writable, so a single
  // sendContent() call can block this task for up to ~10 seconds — and
  // since that loop never actually closes the socket on a plain timeout
  // (only stop()s it for a handful of specific hard errors), the SAME
  // stale connection gets retried again on the next flush() of this same
  // response, and the one after that, stacking up into a multi-second
  // (here, ~23s) stall that blocks every page for every client, since
  // this WebServer handles one connection at a time. Left long enough,
  // this also clogs the ESP32's small socket table with zombie
  // connections that are never freed — which is what "site can't be
  // reached" for a NEW visitor actually is: no free socket left to
  // accept them.
  //
  // connected()'s probe can't see this "silently vanished" case (nothing
  // it can check locally says the peer is gone), so instead this times
  // the actual write and treats an abnormally slow one — far beyond what
  // any write on a healthy local AP link should take — as proof enough:
  // force-close the connection right then instead of leaving it to be
  // retried again later, and stop doing any further work for the rest of
  // this response.
  String html;
  html.reserve(4096);
  bool clientDead = false;
  auto flush = [&]()
  {
    if (clientDead)
    {
      html = "";
      return;
    }
    if (html.length() > 0)
    {
      if (!webServer.client().connected())
      {
        clientDead = true;
        html = "";
        return;
      }
      unsigned long writeStartMs = millis();
      webServer.sendContent(html);
      unsigned long writeMs = millis() - writeStartMs;
      if (writeMs > 300)
      {
        Serial.printf("Web: client write took %lums — treating connection as dead, closing it\n", writeMs);
        webServer.client().stop();
        clientDead = true;
      }
      html = "";
    }
  };
  auto mayFlush = [&]()
  {
    if (html.length() >= 4096)
      flush();
  };
  if (!fragMode)
  {
    html = "<!DOCTYPE html><html lang='en'><head>";
    html += HEAD_COMMON;
    html += "<title>IntelliControl</title></head><body>";

    // Page-shell script: menu / drawer helpers, tab switching, and the helpers
    // a tab's own inline <script> (moved into that tab's panel markup below)
    // relies on. Emitted once, before any panel content, so those helpers
    // exist by the time a panel's script runs — whether that's this same
    // full-page load, or a later fragment swapped in by showTab().
    html += "<script>";
    html += SHELL_JS;
    html += "var __currentTab='" + activeTab + "';";
    html += SHELL_TAB_JS;
    html += "</script>";
    mayFlush(); // flush <head>+shell script immediately

    html += topbarHtml();
    mayFlush(); // flush top bar before building the sidebar, keeping the buffer small
    html += "<div class='layout'>";
    html += sidebarHtml(role, activeTab);
    mayFlush(); // flush sidebar

    html += "<main class='main-content'>";
  } // end if (!fragMode) — shell (head/topbar/sidebar/main-content-open)

  // ====== HOME PANEL ======
  if (isHome)
  {
    html += "<div id='tab-home' class='page'>";
    html += panelHead("home", "Home", "Live status of the PLC and its mobile connection");
    html += "<div class='grid'>";

    // --- BLE Connection Card ---
    {
      const char *state, *bleLabel;
      String userLabel = "";
      if (deviceConnected && authenticated)
      {
        state = "on";
        bleLabel = "Connected";
        if (connectedUserEmail[0] != '\0')
        {
          userLabel = String(connectedUserEmail);
          for (int _bi = 0; _bi < userCount; _bi++)
          {
            if (String(users[_bi].email).equalsIgnoreCase(connectedUserEmail))
            {
              userLabel = String(users[_bi].name);
              break;
            }
          }
        }
      }
      else if (deviceConnected)
      {
        state = "wait";
        bleLabel = "Authenticating...";
      }
      else
      {
        state = "off";
        bleLabel = "Not connected";
      }
      html += "<div class='card stat'>";
      html += "<div class='stat-head'><span class='stat-icon'><i class='ic ic-bluetooth'></i></span>"
              "<div><div class='stat-title'>Mobile connection</div><div class='stat-sub'>Bluetooth (BLE)</div></div></div>";
      html += "<div><span id='hble-conn' class='pill pill-" + String(state) + "'><span class='dot'></span>"
                                                                              "<span id='hble-txt'>" +
              String(bleLabel) + "</span></span></div>";
      html += "<div id='hble-user' class='meta'" + String(userLabel.length() > 0 ? "" : " hidden") + ">"
                                                                                                     "<span class='meta-k'>Signed in as</span><span class='meta-v' id='hble-uname'>" +
              htmlEsc(userLabel) +
              "</span></div>";
      html += "<div class='meta'><span class='meta-k'>Advertised as</span><span class='meta-v'>" + htmlEsc(String(bleName)) +
              "</span></div>";
      html += "</div>";
    }

    // --- Motion Status Card ---
    {
      bool anyMotion = motionUp || motionDown || motionLeft || motionRight;
      html += "<div class='card stat'>";
      html += "<div class='stat-head'><span class='stat-icon warn'><i class='ic ic-activity'></i></span>"
              "<div><div class='stat-title'>Motion status</div><div class='stat-sub' id='hmot-sum'>" +
              String(anyMotion ? "Motion active" : "No active motion") + "</div></div></div>";
      html += "<div class='motion-grid' id='hmot-status'>";
      // Web status reflects E-STOP output state: LOW (motionEstop false) is shown as active.
      html += motionChip("estop", "octagon", "E-STOP", !motionEstop);
      html += motionChip("up", "up", "UP", motionUp);
      html += motionChip("down", "down", "DOWN", motionDown);
      html += motionChip("left", "left", "LEFT", motionLeft);
      html += motionChip("right", "right", "RIGHT", motionRight);
      html += "</div></div>";
    }
    html += "</div>"; // end grid

    // --- System card ---
    html += "<div class='card'><h2 class='section-h'>System</h2><dl class='kv'>";
    html += kvItem("Firmware", FIRMWARE_VERSION);
    html += kvItem("Bluetooth name", htmlEsc(String(bleName)));
    html += kvItem("Wi-Fi network", htmlEsc(String(wifiSsid)));
    html += kvItem("Real-time clock", rtcOk ? "<span class='badge badge-ok'>Running</span>"
                                            : "<span class='badge badge-warn'>Not detected</span>");
    html += kvItem("SD card", sdOk ? "<span class='badge badge-ok'>Ready</span>"
                                   : "<span class='badge badge-warn'>Not available</span>");
    if (isAdmin)
    {
      html += kvItem("Registered users", String(userCount) + " / " + String(MAX_USERS));
      html += kvItem("Registered devices", String(deviceCount) + " / " + String(MAX_DEVICES));
    }
    html += "</dl></div>";

    // A poll whose connection quietly dies mid-flight (WiFi hiccup, weak
    // signal) but is never aborted by the browser leaves the ESP32 no
    // clean TCP close to notice either — it just sits there as a zombie
    // socket, one of the ESP32's very few, until the server-side detection
    // eventually times it out (up to ~10s). Aborting client-side well
    // before the next poll fires means the browser sends a real reset
    // instead, so the ESP32 can free that socket immediately rather than
    // accumulating stale connections in the background every 3 seconds —
    // exactly the kind of buildup that leaves a *later*, unrelated page
    // navigation stuck waiting behind them.
    html += "<script>";
    html += HOME_JS;
    html += "</script>";

    html += "</div>"; // end tab-home
    mayFlush();       // flush home panel
  }

  // ====== USERS PANEL ======
  if (isAdmin && isUsers)
  {
    String addBtn = userCount < MAX_USERS ? "<a href='/add' class='btn btn-primary'><i class='ic ic-plus'></i>Add user</a>" : "";
    html += "<div id='tab-users' class='page'>";
    html += panelHead("users", "User Management", "Everyone who can sign in to the mobile app and this portal", addBtn);

    html += "<div class='card card-flush'>";
    html += "<div class='card-head'><h2>Registered users</h2><span class='grow'></span>"
            "<span class='badge badge-blue'><i class='ic ic-users'></i>" +
            String(userCount) + " / " + String(MAX_USERS) +
            "</span></div>";
    html += "<div class='table-wrap'><table class='stack'><thead><tr>"
            "<th>User</th><th>Role</th><th>Access</th><th class='col-actions'>Actions</th>"
            "</tr></thead><tbody>";
    for (int i = 0; i < userCount; i++)
    {
      String idx = String(i);
      String uname = String(users[i].name);
      html += "<tr><td class='cell-main'><div class='cell-user'><span class='avatar'>" + htmlEsc(initialOf(uname)) +
              "</span><div><b>" + htmlEsc(uname) + "</b><small>" + htmlEsc(String(users[i].email)) + "</small></div></div></td>";
      html += "<td data-label='Role'>" + roleBadge(users[i].role) + "</td>";
      html += "<td data-label='Access'>" + accessCell(users[i]) + "</td>";
      html += "<td class='col-actions'><div class='actions'>";
      if (isSuper || String(users[i].role) != "Admin")
      {
        html += actionLink("/edit?idx=" + idx, "btn-outline", "edit", "Edit", "Edit user");
        html += actionLink("/login-as?idx=" + idx, "btn-outline", "login", "Login as", "Sign in as this user");
        html += actionLink("/confirm-delete?idx=" + idx, "btn-danger-outline", "trash", "Delete", "Delete user");
      }
      else
      {
        html += "<span class='badge'><i class='ic ic-shield'></i>Super Admin only</span>";
      }
      html += "</div></td></tr>";
      mayFlush();
    }
    if (userCount == 0)
    {
      html += "<tr><td colspan='4' class='empty'>No users yet. Use &ldquo;Add user&rdquo; to create the first one.</td></tr>";
    }
    html += "</tbody></table></div></div>";
    html += "</div>"; // end tab-users
  } // end if(isAdmin) users panel
  mayFlush(); // flush users panel

  // ====== DEVICES PANEL ======
  if (isAdmin && isDevices)
  {
    html += "<div id='tab-devices' class='page'>";
    html += panelHead("phone", "Device Registry", "Mobile devices allowed to connect (maximum " + String(MAX_DEVICES) + ")");

    if (deviceCount < MAX_DEVICES)
    {
      html += "<div class='card'><h2 class='section-h'>Register a device</h2>";
      html += "<form method='POST' action='/devices' class='inline-form'>";
      html += "<div class='form-group'><label for='dev-id'>Device ID</label>"
              "<input id='dev-id' type='text' name='id' placeholder='Device ID' required maxlength='40' autocomplete='off'></div>";
      html += "<div class='form-group'><label for='dev-owner'>Owner email <span class='opt'>(optional)</span></label>"
              "<input id='dev-owner' type='text' name='owner' placeholder='owner@example.com' maxlength='64' autocomplete='off'></div>";
      html += "<button type='submit' class='btn btn-primary'><i class='ic ic-plus'></i>Register</button>";
      html += "</form></div>";
    }
    else
    {
      html += alertHtml("info", "The registry is full. Delete a device to register another one.");
    }

    html += "<div class='card card-flush'>";
    html += "<div class='card-head'><h2>Registered devices</h2><span class='grow'></span>"
            "<span class='badge badge-blue'><i class='ic ic-phone'></i>" +
            String(deviceCount) + " / " + String(MAX_DEVICES) +
            "</span></div>";
    html += "<div class='table-wrap'><table class='stack'><thead><tr>"
            "<th>Device ID</th><th>Owner</th><th class='col-actions'>Actions</th></tr></thead><tbody>";
    for (int i = 0; i < deviceCount; i++)
    {
      String owner = String(devices[i].owner);
      html += "<tr><td class='cell-main'><span class='mono'>" + htmlEsc(String(devices[i].id)) + "</span></td>";
      html += "<td data-label='Owner'>" + (owner.length() > 0 ? htmlEsc(owner) : String("&mdash;")) + "</td>";
      html += "<td class='col-actions'><div class='actions'>";
      html += "<form method='POST' action='/devices/delete'>";
      html += "<input type='hidden' name='idx' value='" + String(i) + "'>";
      html += "<button type='submit' class='btn btn-sm btn-danger-outline' title='Delete device' aria-label='Delete device'>"
              "<i class='ic ic-trash'></i><span class='lbl'>Delete</span></button>";
      html += "</form></div></td></tr>";
    }
    if (deviceCount == 0)
    {
      html += "<tr><td colspan='3' class='empty'>No devices registered.</td></tr>";
    }
    html += "</tbody></table></div></div>";
    html += "</div>"; // end tab-devices
  }
  mayFlush();

  // ====== OTA FIRMWARE UPDATE PANEL ======
  if (isAdmin && isOta)
  {
    html += "<div id='tab-ota' class='page page-narrow'>";
    html += panelHead("cloud", "Firmware Update", "Upload a new firmware (.bin) image to update this device over the network.");
    html += "<div class='card'>";
    html += "<div class='form-group'><span class='field-label'>Current firmware version</span><div><strong>" FIRMWARE_VERSION "</strong></div></div>";
    html += alertHtml("warn", "All outputs (including any active motion output) will be forced OFF and E-STOP latched the instant the upload starts. The device will restart automatically once the update finishes. Do not close this page, remove power, or leave the machine unattended until it reconnects.");
    html += "<form id='ota-form' method='POST' action='/ota' enctype='multipart/form-data'>";
    html += "<div class='form-group'><label for='ota-file'>Firmware file (.bin)</label>";
    html += "<input id='ota-file' type='file' name='firmware' accept='.bin' required></div>";
    html += "<div class='form-group'><label class='check' for='ota-confirm'>";
    html += "<input type='checkbox' id='ota-confirm' required><span>I understand outputs will be forced OFF and the device will restart.</span>";
    html += "</label></div>";
    html += "<div class='form-actions'>";
    html += "<button type='submit' id='ota-submit' class='btn btn-primary'><i class='ic ic-upload'></i>Upload &amp; update</button>";
    html += "</div>";
    html += "<div id='ota-status'></div>";
    html += "</form>";
    html += "</div>"; // end card
    html += R"JS(<script>
(function(){
var f=document.getElementById('ota-form');
if(!f)return;
f.addEventListener('submit',function(){
document.getElementById('ota-submit').disabled=true;
document.getElementById('ota-status').innerHTML="<div class='alert alert-info'><i class='ic ic-info'></i><div>Uploading firmware — this can take a minute, please wait...</div></div><div class='progress'><i></i></div>";
});
})();
</script>)JS";
    html += "</div>"; // end tab-ota
  }
  mayFlush();

  // ====== CLOUD LINK PANEL ======
  if (isAdmin && isCloud)
  {
    CloudLinkInfo cloud;
    cloudLinkGetInfo(cloud);
    html += "<div id='tab-cloud' class='page page-narrow'>";
    html += panelHead("wifi", "Cloud Link", "Reports this PLC's status to the IntelliKran web app over the Ethernet port. Crane control does not depend on it.");
    if (webServer.hasArg("saved"))
      html += alertHtml("success", "Saved. The PLC will try to connect within a few seconds.");
    html += "<div class='card'><dl class='kv'>";
    html += kvItem("Status", htmlEsc(String(cloud.state)));
    html += kvItem("PLC ID", cloud.configured ? htmlEsc(String(cloud.plcId)) : String("&mdash;"));
    html += kvItem("Device login", cloud.configured ? htmlEsc(String(cloud.login)) : String("&mdash;"));
    html += kvItem("Last report", cloud.everOk ? String((unsigned long)cloud.lastOkAgoS) + " s ago" : String("None since boot"));
    html += kvItem("Reports sent / failed", String((unsigned long)cloud.okCount) + " / " + String((unsigned long)cloud.failCount));
    html += "</dl></div>";
    html += "<div class='card'>";
    html += "<form method='POST' action='/cloud'>";
    html += "<div class='form-group'><label for='cl-plc'>PLC ID</label><input id='cl-plc' name='plcId' maxlength='32' autocomplete='off' required></div>";
    html += "<div class='form-group'><label for='cl-login'>Device login</label><input id='cl-login' name='login' maxlength='96' autocomplete='off' required></div>";
    html += "<div class='form-group'><label for='cl-key'>Device key</label><input id='cl-key' name='key' type='password' maxlength='64' autocomplete='off' required></div>";
    html += "<div class='form-group'><label for='cl-api'>Web API key</label><input id='cl-api' name='apiKey' maxlength='64' autocomplete='off' required></div>";
    html += alertHtml("info", "Copy these from PLC Fleet in the web app when the PLC is registered, or after choosing New key. The device key cannot be read back from this page.");
    html += "<div class='form-actions'><button type='submit' class='btn btn-primary'>Save</button></div>";
    html += "</form>";
    if (cloud.configured)
    {
      html += "<form method='POST' action='/cloud/clear'><div class='form-actions'>";
      html += "<button type='submit' class='btn btn-outline'>Remove login and stop reporting</button>";
      html += "</div></form>";
    }
    html += "</div>"; // end card
    html += "</div>"; // end tab-cloud
  }
  mayFlush();

  // ====== FIREBASE PANEL (Realtime Database push, Admin only) ======
  if (isAdmin && isFirebase)
  {
    FirebaseSettings fbCfg;
    FirebaseInfo fb;
    cloudLinkGetFirebase(fbCfg, fb);
    memset(fbCfg.secret, 0, sizeof(fbCfg.secret)); // only fb.hasSecret is used below
    html += "<div id='tab-firebase' class='page page-narrow'>";
    html += panelHead("cloud", "Firebase", "Sends this PLC's heartbeat and status to the BLE Face Access device record in the online web app. Crane control does not depend on it.");
    if (webServer.hasArg("saved"))
      html += alertHtml("success", "Saved. The PLC will try to connect within a few seconds.");
    html += "<div class='card'><dl class='kv'>";
    html += kvItem("Status", htmlEsc(String(fb.state)));
    html += kvItem("Push", fb.enabled ? String("Enabled") : String("Disabled"));
    html += kvItem("Device record", fb.deviceId[0] ? "devices/" + htmlEsc(String(fb.deviceId)) : String("&mdash;"));
    html += kvItem("Database secret", fb.hasSecret ? String("Saved") : String("&mdash;"));
    html += kvItem("Last push", fb.everOk ? String((unsigned long)fb.lastOkAgoS) + " s ago" : String("None since boot"));
    html += kvItem("Pushes sent / failed", String((unsigned long)fb.okCount) + " / " + String((unsigned long)fb.failCount));
    html += "</dl></div>";
    html += "<div class='card'>";
    html += "<form method='POST' action='/firebase'>";
    html += "<div class='form-group'><label for='fb-id'>Device ID</label><input id='fb-id' name='deviceId' maxlength='32' autocomplete='off' spellcheck='false' value='" +
            htmlEsc(String(fb.deviceId)) + "' required></div>";
    html += "<div class='form-group'><label for='fb-secret'>Firebase Database Secret</label><input id='fb-secret' name='secret' type='password' maxlength='64' autocomplete='off' placeholder='" +
            String(fb.hasSecret ? "Saved - leave blank to keep it" : "") + "'" + String(fb.hasSecret ? "" : " required") + "></div>";
    html += "<div class='form-group'><label for='fb-url'>Realtime Database URL</label><input id='fb-url' name='dbUrl' maxlength='96' autocomplete='off' spellcheck='false' placeholder='https://your-project-default-rtdb.firebaseio.com' value='" +
            htmlEsc(String(fb.dbUrl)) + "' required></div>";
    html += "<div class='form-group'><label class='check' for='fb-en'><input type='checkbox' id='fb-en' name='enabled' value='1'" +
            String(fb.enabled ? " checked" : "") + "><span>Enable Firebase Push</span></label></div>";
    html += alertHtml("info", "When this device is created in the web app it gets a unique ID. Copy that ID into Device ID. The secret is under Firebase Console &gt; Project settings &gt; Service accounts &gt; Database secrets. It cannot be read back from this page.");
    html += "<div class='form-actions'><button type='submit' class='btn btn-primary'>Save</button></div>";
    html += "</form>";
    if (fb.deviceId[0] || fb.hasSecret || fb.dbUrl[0])
    {
      html += "<form method='POST' action='/firebase/clear'><div class='form-actions'>";
      html += "<button type='submit' class='btn btn-outline'>Remove settings and stop pushing</button>";
      html += "</div></form>";
    }
    html += "</div>"; // end card
    html += "</div>"; // end tab-firebase
  }
  mayFlush();

  // ====== FILES PANEL (SD card) ======
  if (isAdmin && isFiles)
  {
    html += "<div id='tab-files' class='page'>";
    // dir=YYYY-MM shows the inside of a month folder; otherwise the SD root.
    String curDir = webServer.hasArg("dir") ? webServer.arg("dir") : String("");
    if (!validMonthStr(curDir))
      curDir = "";
    html += panelHead("folder", "Files",
                      "Files on the SD card. Event logs are saved in one folder per month (YYYY-MM), one file per day (YYYY-MM-DD.log).");
    if (curDir.length() > 0)
    {
      html += "<div class='crumbs'><a href='/?tab=files' class='btn btn-sm btn-outline'><i class='ic ic-left'></i>All files</a>"
              "<span class='badge badge-blue'><i class='ic ic-folder'></i>" +
              curDir + "</span></div>";
    }

    // Create-new-file form (SD root only)
    if (curDir.length() == 0)
    {
      html += "<div class='card'><h2 class='section-h'>New file</h2>";
      html += "<form method='POST' action='/files/new' class='inline-form'>";
      html += "<div class='form-group'><label for='new-file'>File name</label>"
              "<input id='new-file' type='text' name='name' placeholder='e.g. notes.txt' required maxlength='60' autocomplete='off'></div>";
      html += "<button type='submit' class='btn btn-primary'><i class='ic ic-plus'></i>Create file</button>";
      html += "</form></div>";
    }
    mayFlush();

    File root;
    if (!sdOpen("/" + curDir, FILE_READ, root) || !root.isDirectory())
    {
      html += alertHtml("danger", "SD card not available. Check that the card is inserted.");
    }
    else
    {
      html += "<div class='card card-flush'>";
      html += "<div class='card-head'><h2>" + String(curDir.length() > 0 ? curDir : String("SD card")) + "</h2></div>";
      html += "<div class='table-wrap'><table class='stack'><thead><tr>"
              "<th>File name</th><th>Size</th><th>Entries</th><th class='col-actions'>Actions</th>"
              "</tr></thead><tbody>";
      unsigned long countDeadline = millis() + 2500; // total time allowed for line counting
      int rows = 0;
      File e = root.openNextFile();
      while (e && rows < 100 && !clientDead)
      {
        if (e.isDirectory())
        {
          // Month folders (YYYY-MM) in the root are listed as openable folders.
          String dn = e.name();
          int dsl = dn.lastIndexOf('/');
          if (dsl >= 0)
            dn = dn.substring(dsl + 1);
          if (curDir.length() == 0 && validMonthStr(dn))
          {
            rows++;
            html += "<tr><td class='cell-main'><a class='file-name' href='/?tab=files&dir=" + dn +
                    "'><i class='ic ic-folder'></i>" + dn + "</a></td>";
            html += "<td data-label='Size'>&mdash;</td><td data-label='Entries'>&mdash;</td>";
            html += "<td class='col-actions'><div class='actions'>"
                    "<a href='/?tab=files&dir=" +
                    dn + "' class='btn btn-sm btn-outline'><i class='ic ic-folder'></i>Open folder</a>"
                         "</div></td></tr>";
            mayFlush();
          }
        }
        else
        {
          String nm = e.name();
          int sl = nm.lastIndexOf('/');
          if (sl >= 0)
            nm = nm.substring(sl + 1);
          String pathName = curDir.length() > 0 ? curDir + "/" + nm : nm; // name as used by /files/* routes
          long entries = countEntries(e, countDeadline);
          rows++;
          html += "<tr><td class='cell-main'><span class='file-name'><i class='ic ic-file'></i>" + htmlEsc(nm) + "</span></td>";
          html += "<td data-label='Size'>" + formatSize(e.size()) + "</td>";
          html += "<td data-label='Entries'>" + (entries >= 0 ? String(entries) : String("&mdash;")) + "</td>";
          html += "<td class='col-actions'><div class='actions'>";
          if (validSdName(nm))
          {
            String q = urlEnc(pathName);
            html += actionLink("/files/download?name=" + q, "btn-outline", "download", "Download", "Download file");
            html += actionLink("/files/edit?name=" + q, "btn-outline", "edit", "View / Edit", "View or edit file");
            html += actionLink("/files/confirm-delete?name=" + q, "btn-danger-outline", "trash", "Delete", "Delete file");
          }
          else
          {
            html += "<span class='badge'>Unsupported name</span>";
          }
          html += "</div></td></tr>";
          mayFlush();
        }
        e.close();
        e = root.openNextFile();
      }
      if (e)
        e.close();
      root.close();
      if (rows == 0)
      {
        html += "<tr><td colspan='4' class='empty'>No files on the SD card yet.</td></tr>";
      }
      html += "</tbody></table></div></div>";
    }
    html += "</div>"; // end tab-files
  }
  mayFlush();

  // ====== OUTPUT CONFIG PANEL ======
  if ((isAdmin || isOperator) && isOutConfig)
  {
    bool savedOk = webServer.hasArg("saved");
    bool dupErr = webServer.hasArg("err") && webServer.arg("err") == "dup";
    html += "<div id='tab-outconfig' class='page'>";
    html += panelHead("sliders", "Output Configuration",
                      "Assign each physical output pin to a DF function and choose the motion for that pin.");
    if (savedOk)
    {
      html += alertHtml("success", "Configuration saved successfully.");
    }
    if (dupErr)
    {
      html += alertHtml("danger", "Save failed: each output must have a unique function and motion.");
    }
    html += "<form id='oc-form' method='POST' action='/outconfig'>";
    html += "<div class='card card-flush'>";
    html += "<div class='table-wrap'><table class='stack stack-form stack-pair'>";
    html += "<thead><tr><th>Physical pin</th><th>Digital function</th><th>Motion</th></tr></thead>";
    html += "<tbody>";

    // Build one select dropdown row for each physical output pin
    for (int p = 0; p < NUM_OUTPUT_PINS; p++)
    {
      uint8_t currentFunction = pinMotionConfig[p].function;
      uint8_t currentMotion = pinMotionConfig[p].motion;
      html += "<tr><td class='cell-main'><span class='pin'>" + String(OUTPUT_PINS[p].label) + "</span></td>";
      html += "<td data-label='Digital function'><select name='pin_" + String(p) + "_function' aria-label='Digital function for " +
              String(OUTPUT_PINS[p].label) + "'>";
      for (int f = 0; f < NUM_OUTPUT_PINS; f++)
      {
        html += "<option value='" + String(f) + "'" + String(currentFunction == f ? " selected" : "") + ">" + String(OUTPUT_FUNCTIONS[f]) + "</option>";
      }
      html += "</select></td>";
      html += "<td data-label='Motion'><select name='pin_" + String(p) + "_motion' aria-label='Motion for " +
              String(OUTPUT_PINS[p].label) + "'>";
      html += "<option value='0'" + String(currentMotion == MOTION_NONE ? " selected" : "") + ">";
      html += "&#8212; None &#8212;</option>";
      uint8_t motions[] = {MOTION_ESTOP, MOTION_UP, MOTION_DOWN, MOTION_LEFT, MOTION_RIGHT};
      for (int m = 0; m < 5; m++)
      {
        uint8_t motionId = motions[m];
        html += "<option value='" + String(motionId) + "'" + String(currentMotion == motionId ? " selected" : "") + ">" + String(getMotionLabel(motionId)) + "</option>";
      }
      html += "</select></td></tr>";
    }

    html += "</tbody></table></div>";
    html += "</div>"; // end card
    html += "<div id='oc-save-msg' class='alert alert-info' hidden></div>";
    html += "<div class='form-actions bare'>";
    html += "<button id='oc-save-btn' type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save configuration</button>";
    html += "</div>";
    html += "</form>";

    // Output config save without full page reload — travels with this
    // panel's own markup (moved here from the old shared bottom script) so
    // it works both on a full page load and as an AJAX fragment swap.
    html += "<script>";
    html += OC_JS_A;
    html += String(NUM_OUTPUT_PINS);
    html += OC_JS_B;
    html += "</script>";

    html += "</div>"; // end tab-outconfig
    mayFlush();       // flush outconfig panel
  }

  // ====== NETWORK SETTINGS PANEL ======
  if ((isAdmin || isOperator) && isNetwork)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-network' class='page page-narrow'>";
    html += panelHead("wifi", "Network Settings", "Configure the Bluetooth name and the Wi-Fi network this device broadcasts.");
    if (savedOk)
    {
      html += alertHtml("success", "Network settings saved. Restarting device...");
    }
    html += alertHtml("info", "The device restarts automatically after saving new Bluetooth or Wi-Fi credentials. Reconnect to the new Wi-Fi network once it is back.");
    html += "<form id='net-form' method='POST' action='/netconfig'>";
    html += "<div class='card'>";
    html += "<div class='form-row'>";
    html += "<div class='form-group'><label for='net-ble'>Bluetooth device name</label>";
    html += "<input id='net-ble' type='text' name='ble_name' value='" + htmlEsc(String(bleName)) +
            "' placeholder='RRC_' minlength='5' maxlength='10' required pattern='RRC_.{1,6}'>";
    html += "<div class='form-hint'>Starts with RRC_ &middot; 5&ndash;10 characters</div></div>";
    html += "<div class='form-group'><label for='net-ssid'>Wi-Fi network name (SSID)</label>";
    html += "<input id='net-ssid' type='text' name='wifi_ssid' value='" + htmlEsc(String(wifiSsid)) +
            "' minlength='5' maxlength='10' required>";
    html += "<div class='form-hint'>5&ndash;10 characters</div></div>";
    html += "</div>";
    html += "<div class='form-group'><label for='wifi-password'>Wi-Fi password</label>";
    html += passwordField("wifi-password", "wifi_password", "", htmlEsc(String(wifiPassword)), "minlength='8' maxlength='10' required");
    html += "<div class='form-hint'>8&ndash;10 characters</div></div>";
    html += "<div class='form-actions'>";
    html += "<button id='net-save-btn' type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save network settings</button>";
    html += "</div>";
    html += "</div>"; // end card
    html += "</form>";
    html += "</div>"; // end tab-network
    mayFlush();
  }

  // ====== TIME & DATE PANEL ======
  if ((isAdmin || isOperator) && isTime)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-time' class='page'>";
    html += panelHead("clock", "Time &amp; Date",
                      "View and correct the device's real-time clock, used to timestamp SD card event logs.");
    if (savedOk)
    {
      html += alertHtml("success", "Device time updated.");
    }
    if (!rtcOk)
    {
      html += alertHtml("danger", "RTC hardware not detected — event log entries will show N/A for timestamp until this is resolved.");
    }
    html += "<div class='grid'>";
    {
      String now = currentTimestamp(); // "YYYY-MM-DD HH:MM:SS", or "N/A"
      html += "<div class='card'><div class='stat-title'>Current device time</div>";
      if (now.length() == 19)
      {
        html += "<div class='clock'>" + now.substring(11) + "</div>";
        html += "<div class='clock-date'>" + now.substring(0, 10) + "</div>";
      }
      else
      {
        html += "<div class='clock'>" + htmlEsc(now) + "</div>";
      }
      html += "</div>";
    }
    if (rtcOk)
    {
      String isoNow = currentTimestamp();
      isoNow.replace(" ", "T");
      html += "<div class='card'><form id='time-form' method='POST' action='/timeconfig'>";
      html += "<div class='form-group'><label for='device-time'>Set new date &amp; time</label>";
      html += "<input id='device-time' type='datetime-local' name='device_time' step='1' value='" + isoNow + "' required></div>";
      html += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Set device time</button>";
      html += "</form></div>";
    }
    html += "</div>"; // end grid
    html += "</div>"; // end tab-time
    mayFlush();
  }

  // ====== INPUT CONFIGURATION PANEL ======
  if ((isAdmin || isOperator) && isInConfig)
  {
    bool savedOk = webServer.hasArg("saved");
    html += "<div id='tab-inconfig' class='page'>";
    html += panelHead("cpu", "Input Configuration",
                      "I0.7 and I0.8 share their pin with A0.7/A0.8 — choose digital or analog mode for each, then assign the input used for the mobile remote control.");
    if (savedOk)
    {
      html += alertHtml("success", "Input configuration saved.");
    }
    html += "<script>function icOnRemoteChange(sel){if(sel.value=='1'){var all=document.querySelectorAll(\"select[name$='_remote']\");for(var i=0;i<all.length;i++){if(all[i]!==sel)all[i].value='0';}}}</script>";
    html += "<form method='POST' action='/inconfig'>";
    html += "<div class='card card-flush'>";
    html += "<div class='table-wrap'><table class='stack stack-form'>";
    html += "<thead><tr><th>Input</th><th>Mode</th><th>Assign</th></tr></thead><tbody>";
    for (int i = 0; i < NUM_INPUT_PINS; i++)
    {
      html += "<tr><td class='cell-main'><span class='pin'>" + String(INPUT_PINS[i].label) + "</span></td>";
      html += "<td data-label='Mode'>";
      if (INPUT_PINS[i].switchable)
      {
        html += "<select name='in_" + String(i) + "_mode' aria-label='Mode for " + String(INPUT_PINS[i].label) + "'>";
        html += "<option value='0'" + String(inputMode[i] == INPUT_MODE_DIGITAL ? " selected" : "") + ">Digital (" + String(INPUT_PINS[i].label) + ")</option>";
        html += "<option value='1'" + String(inputMode[i] == INPUT_MODE_ANALOG ? " selected" : "") + ">Analog (" + String(INPUT_PINS[i].analogLabel) + ")</option>";
        html += "</select>";
      }
      else
      {
        html += "<span class='badge'>Digital</span>";
      }
      html += "</td>";
      html += "<td data-label='Assign'>";
      html += "<select name='in_" + String(i) + "_remote' onchange='icOnRemoteChange(this)' aria-label='Assignment for " + String(INPUT_PINS[i].label) + "'>";
      html += "<option value='0'" + String(remoteInputIdx == i ? "" : " selected") + ">None</option>";
      html += "<option value='1'" + String(remoteInputIdx == i ? " selected" : "") + ">Remote Control</option>";
      html += "</select>";
      html += "</td></tr>";
    }
    html += "</tbody></table></div>";
    html += "</div>"; // end card

    html += "<div class='form-actions bare'>";
    html += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save input configuration</button>";
    html += "</div>";
    html += "</form>";
    html += "</div>"; // end tab-inconfig
    mayFlush();
  }

  if (!fragMode)
  {
    html += "</main>"; // end main-content
    html += "</div>";  // end layout
    html += "</body></html>";
  }
  flush(); // send final chunk and close chunked response
  // Same dead-client guard as flush() above — a zero-length chunk write
  // to an already-gone (or just-detected-and-closed) client would
  // otherwise pay the same retry cost.
  if (!clientDead && webServer.client().connected())
    webServer.sendContent(""); // zero-length chunk = end of chunked transfer
}

// ============================================================
//  Add User
// ============================================================
static void handleAddGet()
{
  if (!webAuthAdmin())
    return;
  if (userCount >= MAX_USERS)
  {
    String full = pageHead("Add User", "Max users reached", "users", "users");
    full += alertHtml("info", "Maximum users reached (" + String(MAX_USERS) + ").");
    full += backButton("/?tab=users");
    full += pageFoot();
    sendSafe(200, "text/html", full);
    return;
  }
  String html = pageHead("Add User", "Create a new login for the mobile app and this portal", "users", "users");
  html += "<div class='card'>";
  html += "<form method='POST' action='/add'>";
  html += "<div class='form-row'>";
  html += "<div class='form-group'><label for='add-name'>Full name</label>";
  html += "<input id='add-name' type='text' name='name' placeholder='e.g. John Smith' required autofocus></div>";
  html += "<div class='form-group'><label for='add-email'>Email address</label>";
  html += "<input id='add-email' type='email' name='email' placeholder='user@example.com' required></div>";
  html += "</div>";
  html += "<div class='form-row'>";
  html += "<div class='form-group'><label for='add-pass'>Password</label>";
  html += passwordField("add-pass", "password", "Minimum 6 characters", String(), "required minlength='6'");
  html += "</div>";
  html += "<div class='form-group'><label for='add-role'>Role</label><select name='role' id='add-role'>";
  html += "<option value='Operator'>Operator</option>";
  if (currentRole() == "SuperAdmin") // only the Super Admin may create Admins
    html += "<option value='Admin'>Admin</option>";
  html += "</select></div>";
  html += "</div>";
  html += accessFormFields(nullptr);
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Add user</button>";
  html += backButton("/?tab=users", "Cancel");
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleAddPost()
{
  Serial.printf("Web: POST /add — accessType='%s' from='%s' to='%s'\n",
                webServer.arg("accessType").c_str(), webServer.arg("fromTime").c_str(), webServer.arg("toTime").c_str());
  if (!webAuthAdmin())
  {
    Serial.println("Web: POST /add rejected — not an authenticated admin session");
    return;
  }
  if (userCount >= MAX_USERS)
  {
    sendSafe(400, "text/html", errorPage("Max users reached.", "/"));
    return;
  }
  String name = webServer.arg("name");
  String email = webServer.arg("email");
  String password = webServer.arg("password");
  String role = webServer.arg("role");
  if (name.length() == 0 || email.length() == 0 || password.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name, email and password are required.", "/add"));
    return;
  }
  if (role != "Admin" && role != "Operator")
    role = "Operator";
  if (role == "Admin" && currentRole() != "SuperAdmin")
  {
    sendSafe(403, "text/html", errorPage("Only the Super Admin can add Admin accounts.", "/add"));
    return;
  }
  for (int i = 0; i < userCount; i++)
  {
    if (email.equalsIgnoreCase(users[i].email))
    {
      sendSafe(400, "text/html", errorPage("Email already exists.", "/add"));
      return;
    }
  }
  User newUser = {};
  String accessErr = readAccessFromForm(newUser);
  if (accessErr.length() > 0)
  {
    Serial.printf("Web: POST /add rejected — %s\n", accessErr.c_str());
    sendSafe(400, "text/html", errorPage(accessErr, "/add"));
    return;
  }
  name.toCharArray(users[userCount].name, sizeof(users[userCount].name));
  email.toCharArray(users[userCount].email, sizeof(users[userCount].email));
  password.toCharArray(users[userCount].password, sizeof(users[userCount].password));
  role.toCharArray(users[userCount].role, sizeof(users[userCount].role));
  users[userCount].accessType = newUser.accessType;
  users[userCount].startTs = newUser.startTs;
  users[userCount].endTs = newUser.endTs;
  userCount++;
  Serial.println("Web: saving users to NVS...");
  if (!saveUsers())
  {
    userCount--; // roll back: the new user could not be stored persistently
    sendSafe(500, "text/html", errorPage("Could not save the user to device storage (storage full?). The user was not added.", "/?tab=users"));
    return;
  }
  Serial.printf("Web: user added — %s (%s)\n", users[userCount - 1].email,
                users[userCount - 1].accessType == ACCESS_TIMED ? "timed" : "perpetual");
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Devices POST — add new device (Admin only)
// ============================================================
static void handleDevicesPost()
{
  if (!webAuthAdmin())
    return;
  String id = webServer.arg("id");
  String owner = webServer.arg("owner");
  id.trim();
  owner.trim();
  if (id.length() == 0 || id.length() > 40)
  {
    sendSafe(400, "text/html", errorPage("Device ID required and must be 1-40 characters.", "/?tab=devices"));
    return;
  }
  // prevent duplicate
  for (int i = 0; i < deviceCount; i++)
  {
    if (id == String(devices[i].id))
    {
      sendSafe(400, "text/html", errorPage("Device ID already registered.", "/?tab=devices"));
      return;
    }
  }
  // add
  if (deviceCount >= MAX_DEVICES)
  {
    sendSafe(400, "text/html", errorPage("Device registry full.", "/?tab=devices"));
    return;
  }
  id.toCharArray(devices[deviceCount].id, sizeof(devices[deviceCount].id));
  owner.toCharArray(devices[deviceCount].owner, sizeof(devices[deviceCount].owner));
  deviceCount++;
  saveDevices();
  webServer.sendHeader("Location", "/?tab=devices");
  sendSafe(303);
}

// ============================================================
//  Cloud Link POST — store the device login (Admin only)
// ============================================================
static void handleCloudPost()
{
  if (!webAuthAdmin())
    return;
  if (!cloudLinkAvailable())
  {
    sendSafe(404, "text/html", errorPage("Cloud Link is not enabled in this firmware.", "/"));
    return;
  }
  String plcId = webServer.arg("plcId");
  String login = webServer.arg("login");
  String key = webServer.arg("key");
  String apiKey = webServer.arg("apiKey");
  plcId.trim();
  login.trim();
  key.trim();
  apiKey.trim();
  if (!cloudValidPlcId(plcId.c_str()))
  {
    sendSafe(400, "text/html", errorPage("PLC ID must be 3-32 lower-case letters, digits or hyphens.", "/?tab=cloud"));
    return;
  }
  if (login.length() == 0 || login.length() > 96 || key.length() == 0 || key.length() > 64)
  {
    sendSafe(400, "text/html", errorPage("Device login and device key are required.", "/?tab=cloud"));
    return;
  }
  if (!cloudValidApiKey(apiKey.c_str()))
  {
    sendSafe(400, "text/html", errorPage("Web API key is not valid.", "/?tab=cloud"));
    return;
  }
  if (!cloudLinkSave(plcId, login, key, apiKey))
  {
    sendSafe(500, "text/html", errorPage("Could not save to device storage.", "/?tab=cloud"));
    return;
  }
  webServer.sendHeader("Location", "/?tab=cloud&saved=1");
  sendSafe(303);
}

static void handleCloudClearPost()
{
  if (!webAuthAdmin())
    return;
  cloudLinkClear();
  webServer.sendHeader("Location", "/?tab=cloud");
  sendSafe(303);
}

// ============================================================
//  Firebase POST — store the Realtime Database settings (Admin only)
// ============================================================
static void handleFirebasePost()
{
  if (!webAuthAdmin())
    return;
  String id = webServer.arg("deviceId");
  String url = webServer.arg("dbUrl");
  String secret = webServer.arg("secret");
  id.trim();
  url.trim();
  secret.trim();
  bool enabled = webServer.hasArg("enabled");

  FirebaseSettings cur;
  FirebaseInfo info;
  cloudLinkGetFirebase(cur, info);
  if (secret.length() == 0)
    secret = cur.secret; // left blank: keep the saved one

  char host[80] = "";
  if (id.length() > 0 && !cloudValidDeviceId(id.c_str()))
  {
    sendSafe(400, "text/html", errorPage("Device ID must be 1-32 letters, digits, '-' or '_'. Copy it exactly from the web app.", "/?tab=firebase"));
    return;
  }
  if (secret.length() > 0 && !cloudValidDbSecret(secret.c_str()))
  {
    sendSafe(400, "text/html", errorPage("Database secret is not valid (letters, digits, '-', '_' and '.' only, up to 64).", "/?tab=firebase"));
    return;
  }
  if (url.length() > 0 && !cloudParseDbHost(url.c_str(), host, sizeof(host)))
  {
    sendSafe(400, "text/html", errorPage("Database URL must be an https:// address ending in .firebaseio.com or .firebasedatabase.app.", "/?tab=firebase"));
    return;
  }
  if (enabled && (id.length() == 0 || secret.length() == 0 || url.length() == 0))
  {
    sendSafe(400, "text/html", errorPage("Device ID, database secret and database URL are all needed to enable Firebase Push.", "/?tab=firebase"));
    return;
  }

  FirebaseSettings next = {};
  next.enabled = enabled;
  strlcpy(next.deviceId, id.c_str(), sizeof(next.deviceId));
  strlcpy(next.secret, secret.c_str(), sizeof(next.secret));
  if (url.length() > 0)
    snprintf(next.dbUrl, sizeof(next.dbUrl), "https://%s", host); // stored without any trailing slash
  bool saved = cloudLinkSaveFirebase(next);
  memset(&next, 0, sizeof(next));
  memset(&cur, 0, sizeof(cur));
  if (!saved)
  {
    sendSafe(500, "text/html", errorPage("Could not save to device storage.", "/?tab=firebase"));
    return;
  }
  webServer.sendHeader("Location", "/?tab=firebase&saved=1");
  sendSafe(303);
}

static void handleFirebaseClearPost()
{
  if (!webAuthAdmin())
    return;
  cloudLinkClearFirebase();
  webServer.sendHeader("Location", "/?tab=firebase");
  sendSafe(303);
}

// ============================================================
//  Devices DELETE — remove device by index (Admin only)
// ============================================================
static void handleDeleteDevicePost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= deviceCount)
  {
    sendSafe(404, "text/html", errorPage("Device not found.", "/?tab=devices"));
    return;
  }
  for (int i = idx; i < deviceCount - 1; i++)
  {
    devices[i] = devices[i + 1];
  }
  deviceCount--;
  saveDevices();
  webServer.sendHeader("Location", "/?tab=devices");
  sendSafe(303);
}

// ============================================================
//  OTA Firmware Update  (Admin only)
// ============================================================
// otaAuthorized/otaErrorMsg are set at UPLOAD_FILE_START and checked on
// every subsequent chunk: this is the actual security boundary for the
// upload (it gates every Update.write() call), not just the final
// handler below — webAuthAdmin()'s redirect can't be used mid-upload,
// so authorization here is a plain currentRole() check instead.
static bool otaAuthorized = false;
static String otaErrorMsg = "";

static void handleOtaUpload()
{
  HTTPUpload &upload = webServer.upload();
  if (upload.status == UPLOAD_FILE_START)
  {
    otaErrorMsg = "";
    otaAuthorized = isManagerRole(currentRole());
    if (!otaAuthorized)
    {
      otaErrorMsg = "Admin privileges required.";
      return;
    }
    Serial.printf("Web: OTA update starting — file=%s\n", upload.filename.c_str());
    // Safe state before any flash write begins: outputs off, E-STOP
    // latched, same as this device's own boot-time safe state.
    forceAllOutputsOff();
    if (!Update.begin(UPDATE_SIZE_UNKNOWN))
    {
      otaErrorMsg = "Could not start update (image too large for the inactive partition, or update already in progress).";
      Update.printError(Serial);
    }
  }
  else if (upload.status == UPLOAD_FILE_WRITE)
  {
    if (otaAuthorized && otaErrorMsg.length() == 0)
    {
      if (Update.write(upload.buf, upload.currentSize) != upload.currentSize)
      {
        otaErrorMsg = "Write failed mid-upload.";
        Update.printError(Serial);
        Update.abort(); // release the update session now rather than leaving it half-open until END
      }
    }
  }
  else if (upload.status == UPLOAD_FILE_END)
  {
    if (otaAuthorized && otaErrorMsg.length() == 0)
    {
      if (Update.end(true))
      {
        Serial.printf("Web: OTA update received — %u bytes, verifying and rebooting\n", (unsigned)upload.totalSize);
      }
      else
      {
        otaErrorMsg = "Update did not verify (corrupt upload or wrong image type).";
        Update.printError(Serial);
      }
    }
  }
  else if (upload.status == UPLOAD_FILE_ABORTED)
  {
    Update.abort();
    otaErrorMsg = "Upload aborted.";
  }
}

static void handleOtaComplete()
{
  if (!webAuthAdmin())
    return;
  if (!otaAuthorized || otaErrorMsg.length() > 0)
  {
    String msg = otaErrorMsg.length() > 0 ? otaErrorMsg : "Update failed.";
    sendSafe(400, "text/html", errorPage("Update failed: " + msg, "/?tab=ota"));
    return;
  }
  String html = pageHead("Firmware Update", nullptr, "ota");
  html += stateCard("ok", "check-circle", "Firmware updated",
                    "The new firmware was written successfully. The device is restarting — reconnect once it comes back online.",
                    "<div class='progress'><i></i></div>");
  html += pageFoot();
  sendSafe(200, "text/html", html);
  delay(500);
  ESP.restart();
}

// ============================================================
//  Edit User
// ============================================================
static void handleEditGet()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String html = pageHead("Edit User", "Update login details and access", "users", "users");
  html += "<div class='card'><form method='POST' action='/edit'>";
  html += "<input type='hidden' name='idx' value='" + String(idx) + "'>";
  html += "<div class='form-row'>";
  html += "<div class='form-group'><label for='edit-name'>Full name</label>"
          "<input id='edit-name' type='text' name='name' value='" +
          htmlEsc(String(users[idx].name)) + "' required></div>";
  html += "<div class='form-group'><label for='edit-email'>Email address</label>"
          "<input id='edit-email' type='email' name='email' value='" +
          htmlEsc(String(users[idx].email)) + "' required></div>";
  html += "</div>";
  html += "<div class='form-row'>";
  html += "<div class='form-group'><label for='edit-pass'>Password</label>"
          "<input id='edit-pass' type='text' name='password' value='" +
          htmlEsc(String(users[idx].password)) + "' minlength='6'></div>";
  html += "<div class='form-group'><label for='edit-role'>Role</label><select name='role' id='edit-role'>";
  const char *roles[] = {"Operator", "Admin"};
  int roleCount = (currentRole() == "SuperAdmin") ? 2 : 1; // Admins can only assign Operator
  for (int r = 0; r < roleCount; r++)
  {
    html += "<option value='" + String(roles[r]) + "'";
    if (String(users[idx].role) == roles[r])
      html += " selected";
    html += ">" + String(roles[r]) + "</option>";
  }
  html += "</select></div>";
  html += "</div>";
  html += accessFormFields(&users[idx]);
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save changes</button>";
  html += backButton("/?tab=users", "Cancel");
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleEditPost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String name = webServer.arg("name");
  String email = webServer.arg("email");
  String password = webServer.arg("password");
  String role = webServer.arg("role");
  if (role == "Admin" && currentRole() != "SuperAdmin")
  {
    sendSafe(403, "text/html", errorPage("Only the Super Admin can assign the Admin role.", "/?tab=users"));
    return;
  }
  if (name.length() == 0 || email.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name and email are required.", "/"));
    return;
  }
  if (role != "Admin" && role != "Operator")
    role = "Operator";
  for (int i = 0; i < userCount; i++)
  {
    if (i != idx && email.equalsIgnoreCase(users[i].email))
    {
      sendSafe(400, "text/html", errorPage("Email already in use by another user.", "/"));
      return;
    }
  }
  User newAccess = {};
  String accessErr = readAccessFromForm(newAccess);
  if (accessErr.length() > 0)
  {
    sendSafe(400, "text/html", errorPage(accessErr, ("/edit?idx=" + String(idx)).c_str()));
    return;
  }
  name.toCharArray(users[idx].name, sizeof(users[idx].name));
  email.toCharArray(users[idx].email, sizeof(users[idx].email));
  role.toCharArray(users[idx].role, sizeof(users[idx].role));
  users[idx].accessType = newAccess.accessType;
  users[idx].startTs = newAccess.startTs;
  users[idx].endTs = newAccess.endTs;
  if (password.length() > 0)
  {
    password.toCharArray(users[idx].password, sizeof(users[idx].password));
  }
  saveUsers();
  Serial.printf("Web: user edited — %s\n", users[idx].email);
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Delete User
// ============================================================
static void handleConfirmDelete()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  String html = pageHead("Delete User", nullptr, "users");
  html += confirmDeleteCard("/delete", "idx", String(idx), htmlEsc(String(users[idx].email)), "/?tab=users", "user");
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleDeletePost()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  Serial.printf("Web: user deleted — %s\n", users[idx].email);
  for (int i = idx; i < userCount - 1; i++)
  {
    users[i] = users[i + 1];
  }
  userCount--;
  saveUsers();
  webServer.sendHeader("Location", "/?tab=users");
  sendSafe(303);
}

// ============================================================
//  Account GET — dedicated settings page
// ============================================================
static void handleAccountGet()
{
  if (!webAuth())
    return;
  String _se = currentUserEmail();
  bool isBleUser = _se.length() > 0;
  // For BLE users, show their name/email; for web admin show username
  String currentName = isBleUser ? "" : "";
  String currentId = isBleUser ? _se : String(webAdminUser);
  if (isBleUser)
  {
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(_se))
      {
        currentName = String(users[i].name);
        break;
      }
    }
  }
  String subtitle = isBleUser ? "Change your name and password" : "Change your web panel login credentials";
  // Current password, pre-filled as this form has always done. A signed-in BLE
  // user who has vanished from the list gets an empty field, never the web admin's.
  String curPassVal = "";
  if (isBleUser)
  {
    int ui = findUserIndexByEmail(_se.c_str());
    if (ui >= 0)
      curPassVal = String(users[ui].password);
  }
  else
  {
    curPassVal = String(webAdminPass);
  }
  String html = pageHead("Account Settings", subtitle.c_str(), nullptr, "user");
  html += "<div class='card'>";
  html += "<div class='cell-user account-id'><span class='avatar'>" +
          htmlEsc(initialOf(isBleUser ? currentName : currentId)) + "</span><div><b>" +
          htmlEsc(isBleUser ? currentName : currentId) + "</b><small>" + roleLabel(currentRole()) + "</small></div></div>";
  html += "<form method='POST' action='/account'>";
  if (isBleUser)
  {
    html += "<div class='form-group'><label for='acc-name'>Full name</label>";
    html += "<input id='acc-name' type='text' name='new_user' value='" + htmlEsc(currentName) + "' required></div>";
    html += "<div class='form-group'><label for='acc-email'>Email</label>";
    html += "<input id='acc-email' type='text' value='" + htmlEsc(currentId) + "' disabled></div>";
  }
  else
  {
    html += "<div class='form-group'><label for='acc-email'>Email address</label>";
    html += "<input id='acc-email' type='email' name='new_user' value='" + htmlEsc(currentId) + "' required></div>";
  }
  html += "<div class='form-section'><h3>Change password</h3>";
  html += "<div class='form-group'><label for='acc-cur'>Current password</label>";
  html += "<input id='acc-cur' type='text' name='cur_pass' value='" + htmlEsc(curPassVal) + "' required></div>";
  html += "<div class='form-row'>";
  html += "<div class='form-group'><label for='acc-new'>New password</label>";
  html += passwordField("acc-new", "new_pass", "Leave blank to keep current");
  html += "</div>";
  html += "<div class='form-group'><label for='acc-cfm'>Confirm new password</label>";
  html += passwordField("acc-cfm", "cfm_pass", "Repeat new password");
  html += "</div>";
  html += "</div></div>";
  html += "<div class='form-actions'>";
  html += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save changes</button>";
  html += backButton("/", "Back");
  html += "</div></form></div>";
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

// ============================================================
//  Account POST — change credentials (web admin or BLE user)
// ============================================================
static void handleAccountPost()
{
  if (!webAuth())
    return;
  String newUser = webServer.arg("new_user");
  String curPass = webServer.arg("cur_pass");
  String newPass = webServer.arg("new_pass");
  String cfmPass = webServer.arg("cfm_pass");
  if (newUser.length() == 0)
  {
    sendSafe(400, "text/html", errorPage("Name/username cannot be empty.", "/account"));
    return;
  }
  String _se2 = currentUserEmail();
  bool isBleUser = _se2.length() > 0;
  if (isBleUser)
  {
    // Find the BLE user by session email
    int idx = -1;
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(_se2))
      {
        idx = i;
        break;
      }
    }
    if (idx < 0)
    {
      sendSafe(404, "text/html", errorPage("User session invalid.", "/account"));
      return;
    }
    if (String(users[idx].password) != curPass)
    {
      sendSafe(401, "text/html", errorPage("Current password is incorrect.", "/account"));
      return;
    }
    if (newPass.length() > 0)
    {
      if (newPass != cfmPass)
      {
        sendSafe(400, "text/html", errorPage("New passwords do not match.", "/account"));
        return;
      }
      if (newPass.length() < 6)
      {
        sendSafe(400, "text/html", errorPage("New password must be at least 6 characters.", "/account"));
        return;
      }
      newPass.toCharArray(users[idx].password, sizeof(users[idx].password));
    }
    newUser.toCharArray(users[idx].name, sizeof(users[idx].name));
    saveUsers();
    Serial.printf("Web: user updated own account — %s\n", users[idx].email);
    webServer.sendHeader("Location", "/");
    sendSafe(303);
  }
  else
  {
    // Web admin credentials
    if (String(webAdminPass) != curPass)
    {
      sendSafe(401, "text/html", errorPage("Current password is incorrect.", "/account"));
      return;
    }
    if (newPass.length() > 0)
    {
      if (newPass != cfmPass)
      {
        sendSafe(400, "text/html", errorPage("New passwords do not match.", "/account"));
        return;
      }
      if (newPass.length() < 6)
      {
        sendSafe(400, "text/html", errorPage("New password must be at least 6 characters.", "/account"));
        return;
      }
      newPass.toCharArray(webAdminPass, sizeof(webAdminPass));
    }
    newUser.toCharArray(webAdminUser, sizeof(webAdminUser));
    saveWebAdmin();
    // Invalidate current session so admin re-logs in with new credentials
    int _si2 = findSessionIdx();
    if (_si2 >= 0)
    {
      sessions[_si2].token = "";
      sessions[_si2].role = "";
      sessions[_si2].userEmail = "";
    }
    webServer.sendHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
    webServer.sendHeader("Location", "/login");
    sendSafe(303);
  }
}

// ============================================================
//  Login As (Admin only) — switch web session to a BLE user
// ============================================================
static void handleLoginAs()
{
  if (!webAuthAdmin())
    return;
  int idx = webServer.arg("idx").toInt();
  if (idx < 0 || idx >= userCount)
  {
    sendSafe(404, "text/html", errorPage("User not found.", "/"));
    return;
  }
  if (!webCanManageUser(idx))
    return;
  int _slot2 = findSessionIdx();
  if (_slot2 < 0)
    _slot2 = allocSessionSlot();
  sessions[_slot2].token = generateToken();
  sessions[_slot2].role = String(users[idx].role);
  sessions[_slot2].userEmail = String(users[idx].email);
  sessions[_slot2].timeExempt = true; // admin impersonation is exempt from the timed-access window
  webServer.sendHeader("Set-Cookie", "session=" + sessions[_slot2].token + "; HttpOnly; Path=/");
  Serial.printf("Web: Admin switched session to user — %s (%s)\n", users[idx].email, users[idx].role);
  webServer.sendHeader("Location", "/");
  sendSafe(303);
}

// ============================================================
//  Network Settings POST — change BLE/WiFi credentials
// ============================================================
static void handleNetConfigPost()
{
  if (!webAuthOutputConfig())
    return;
  String newBleName = webServer.arg("ble_name");
  String newSsid = webServer.arg("wifi_ssid");
  String newPass = webServer.arg("wifi_password");

  newBleName.trim();
  newSsid.trim();
  newPass.trim();

  if (newBleName.length() < 5 || newBleName.length() > 10 || !newBleName.startsWith("RRC_"))
  {
    sendSafe(400, "text/html", errorPage("BLE name must start with RRC_ and be 5-10 characters long.", "/?tab=network"));
    return;
  }
  if (newSsid.length() < 5 || newSsid.length() > 10)
  {
    sendSafe(400, "text/html", errorPage("WiFi SSID must be 5-10 characters long.", "/?tab=network"));
    return;
  }
  if (newPass.length() < 8 || newPass.length() > 10)
  {
    sendSafe(400, "text/html", errorPage("WiFi Password must be 8-10 characters long.", "/?tab=network"));
    return;
  }

  newBleName.toCharArray(bleName, sizeof(bleName));
  newSsid.toCharArray(wifiSsid, sizeof(wifiSsid));
  newPass.toCharArray(wifiPassword, sizeof(wifiPassword));
  saveNetworkConfig();

  String html = pageHead("Network Settings", nullptr, "network");
  html += stateCard("ok", "check-circle", "Settings saved",
                    "The device is restarting with its new settings. Reconnect to the new Wi-Fi network and Bluetooth name once it is back.",
                    "<div class='progress'><i></i></div>");
  html += pageFoot();
  sendSafe(200, "text/html", html);
  delay(500);
  ESP.restart();
}

// ============================================================
//  Time & Date POST — corrects the RTC from the web UI
// ============================================================
static void handleTimeConfigPost()
{
  if (!webAuthOutputConfig())
    return;

  if (!rtcOk)
  {
    sendSafe(400, "text/html", errorPage("RTC hardware not detected — cannot set device time.", "/?tab=time"));
    return;
  }

  // Expect HTML datetime-local format: "YYYY-MM-DDTHH:MM" or "YYYY-MM-DDTHH:MM:SS"
  String dt = webServer.arg("device_time");
  int year, month, day, hour, minute, second = 0;
  int matched = sscanf(dt.c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
  if (matched < 5 || year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59)
  {
    sendSafe(400, "text/html", errorPage("Invalid date/time value.", "/?tab=time"));
    return;
  }

  bool ok = setRtcDateTime(year, month, day, hour, minute, second);
  if (!ok)
  {
    Serial.printf("Web: FAILED to set device time to %04d-%02d-%02d %02d:%02d:%02d — write did not verify\n",
                  year, month, day, hour, minute, second);
    sendSafe(500, "text/html", errorPage("Failed to set device time — the RTC did not accept the write. This usually means a wiring/connection "
                                         "problem (e.g. missing pull-up resistors on SDA/SCL, or a loose RTC module). Please check the hardware and try again.",
                                         "/?tab=time"));
    return;
  }
  Serial.printf("Web: device time set to %04d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, minute, second);
  webServer.sendHeader("Location", "/?tab=time&saved=1");
  sendSafe(303);
}

// ============================================================
//  Input Configuration POST — I0.7/I0.8 mode + remote-control input
// ============================================================
static void handleInConfigPost()
{
  if (!webAuthOutputConfig())
    return;

  for (int i = 0; i < NUM_INPUT_PINS; i++)
  {
    if (!INPUT_PINS[i].switchable)
      continue;
    char paramName[16];
    sprintf(paramName, "in_%d_mode", i);
    int m = webServer.arg(paramName).toInt();
    inputMode[i] = (m == INPUT_MODE_ANALOG) ? INPUT_MODE_ANALOG : INPUT_MODE_DIGITAL;
  }

  int8_t newRemote = -1;
  for (int i = 0; i < NUM_INPUT_PINS; i++)
  {
    char paramName[16];
    sprintf(paramName, "in_%d_remote", i);
    if (webServer.arg(paramName).toInt() == 1)
    {
      newRemote = (int8_t)i;
      break;
    }
  }
  remoteInputIdx = newRemote;

  saveInputConfig();
  Serial.println("Web: input configuration updated");
  webServer.sendHeader("Location", "/?tab=inconfig&saved=1");
  sendSafe(303);
}

// ============================================================
//  Motion Status  —  read-only JSON endpoint
// ============================================================
// ============================================================
//  Output Configuration  (POST /outconfig)
// ============================================================
static void handleOutConfigPost()
{
  if (!webAuthOutputConfig())
    return;
  String reqType = webServer.header("X-Requested-With");

  // Parse function and motion assignments for each physical pin
  uint8_t newPinFunctions[NUM_OUTPUT_PINS];
  uint8_t newPinMotions[NUM_OUTPUT_PINS];
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    char paramName[24];
    sprintf(paramName, "pin_%d_function", p);
    String functionStr = webServer.arg(paramName);
    int functionId = functionStr.toInt();

    sprintf(paramName, "pin_%d_motion", p);
    String motionStr = webServer.arg(paramName);
    int motionId = motionStr.toInt();

    newPinFunctions[p] = (functionId >= 0 && functionId < NUM_OUTPUT_PINS) ? (uint8_t)functionId : (uint8_t)p;
    newPinMotions[p] = (motionId >= MOTION_NONE && motionId <= MOTION_RIGHT) ? (uint8_t)motionId : MOTION_NONE;
  }

  // Validate: each physical pin must have a unique digital function
  for (int p1 = 0; p1 < NUM_OUTPUT_PINS; p1++)
  {
    for (int p2 = p1 + 1; p2 < NUM_OUTPUT_PINS; p2++)
    {
      if (newPinFunctions[p1] == newPinFunctions[p2])
      {
        Serial.println("Out config rejected: duplicate digital function assignment");
        if (reqType == "fetch")
        {
          webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
          sendSafe(400, "application/json", "{\"ok\":0,\"msg\":\"Save failed: each output must have a unique digital function.\"}");
          return;
        }
        webServer.sendHeader("Location", "/?tab=outconfig&err=dup");
        sendSafe(303);
        return;
      }
    }
  }

  // Validate: no two pins can be assigned the same motion (unless it's None)
  for (int p1 = 0; p1 < NUM_OUTPUT_PINS; p1++)
  {
    if (newPinMotions[p1] == MOTION_NONE)
      continue;
    for (int p2 = p1 + 1; p2 < NUM_OUTPUT_PINS; p2++)
    {
      if (newPinMotions[p2] == newPinMotions[p1])
      {
        Serial.println("Out config rejected: duplicate motion assignment");
        if (reqType == "fetch")
        {
          webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
          sendSafe(400, "application/json", "{\"ok\":0,\"msg\":\"Save failed: two outputs cannot be assigned the same motion.\"}");
          return;
        }
        webServer.sendHeader("Location", "/?tab=outconfig&err=dup");
        sendSafe(303);
        return;
      }
    }
  }

  // Apply new configuration
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    pinMotionConfig[p].function = newPinFunctions[p];
    pinMotionConfig[p].motion = newPinMotions[p];
  }
  saveOutputConfig();

  Serial.println("Output config updated:");
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    Serial.printf("  %s (%s) → %s\n", OUTPUT_FUNCTIONS[pinMotionConfig[p].function], OUTPUT_PINS[p].label,
                  getMotionLabel(pinMotionConfig[p].motion));
  }

  if (reqType == "fetch")
  {
    webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    sendSafe(200, "application/json", "{\"ok\":1}");
    return;
  }
  webServer.sendHeader("Location", "/?tab=outconfig&saved=1");
  sendSafe(303);
}

// ============================================================
//  Motion status  (GET /motion/status — JSON, used by home page)
// ============================================================
static void handleMotionStatus()
{
  if (!webAuth())
    return;
  String bleUserName = "";
  if (authenticated && connectedUserEmail[0] != '\0')
  {
    bleUserName = String(connectedUserEmail);
    for (int i = 0; i < userCount; i++)
    {
      if (String(users[i].email).equalsIgnoreCase(connectedUserEmail))
      {
        bleUserName = String(users[i].name);
        break;
      }
    }
    bleUserName.replace("\"", "\\\"");
  }

  // Determine which output pins are active based on pin-motion configuration and current motion states
  int estopOutputOn = 0;
  int upOutputOn = 0;
  int downOutputOn = 0;
  int leftOutputOn = 0;
  int rightOutputOn = 0;

  // Check each pin to see if its assigned motion is active
  for (int p = 0; p < NUM_OUTPUT_PINS; p++)
  {
    uint8_t motion = pinMotionConfig[p].motion;
    bool isActive = false;

    switch (motion)
    {
    case MOTION_ESTOP:
      isActive = motionEstop;
      // E-STOP output is inverted: LOW = active
      estopOutputOn = isActive ? 0 : 1;
      break;
    case MOTION_UP:
      isActive = motionUp;
      upOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_DOWN:
      isActive = motionDown;
      downOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_LEFT:
      isActive = motionLeft;
      leftOutputOn = isActive ? 1 : 0;
      break;
    case MOTION_RIGHT:
      isActive = motionRight;
      rightOutputOn = isActive ? 1 : 0;
      break;
    default:
      break;
    }
  }

  String json = "{\"estop\":" + String(estopOutputOn) +
                ",\"up\":" + String(upOutputOn) +
                ",\"down\":" + String(downOutputOn) +
                ",\"left\":" + String(leftOutputOn) +
                ",\"right\":" + String(rightOutputOn) +
                ",\"ble_conn\":" + String(deviceConnected ? 1 : 0) +
                ",\"ble_auth\":" + String(authenticated ? 1 : 0) +
                ",\"ble_user\":\"" + bleUserName + "\"}";
  webServer.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  sendSafe(200, "application/json", json);
}

// ============================================================
//  Files (SD card) — download, view/edit, delete, create
// ============================================================
static void handleFileDownload()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  File f;
  if (!validSdPath(name) || !sdOpen("/" + name, FILE_READ, f) || f.isDirectory())
  {
    sendSafe(404, "text/html", errorPage("File not found.", filesTabUrl(name).c_str()));
    return;
  }
  // Phone browsers (Android Chrome / iOS Safari) are stricter than desktop ones:
  // give them a real MIME type and ask for a one-shot connection so the
  // download manager doesn't try to reuse/resume it (this server has no Range support).
  String lower = name;
  lower.toLowerCase();
  const char *mime = "application/octet-stream";
  if (lower.endsWith(".csv"))
    mime = "text/csv";
  else if (lower.endsWith(".txt") || lower.endsWith(".log"))
    mime = "text/plain";
  else if (lower.endsWith(".json"))
    mime = "application/json";
  webServer.sendHeader("Content-Disposition", "attachment; filename=\"" + name + "\"");
  webServer.sendHeader("Cache-Control", "no-store");
  webServer.sendHeader("Connection", "close");
  webServer.streamFile(f, mime);
  f.close();
}

static void handleFileEditGet()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  File f;
  if (!validSdPath(name) || !sdOpen("/" + name, FILE_READ, f) || f.isDirectory())
  {
    sendSafe(404, "text/html", errorPage("File not found.", filesTabUrl(name).c_str()));
    return;
  }
  size_t size = f.size();
  bool editable = size <= FILE_EDIT_MAX_BYTES;
  bool tailOnly = !editable && size > FILE_VIEW_MAX_BYTES;
  if (tailOnly)
  {
    // Show only the last FILE_VIEW_MAX_BYTES bytes, starting at a line boundary.
    f.seek(size - FILE_VIEW_MAX_BYTES);
    int c;
    while ((c = f.read()) >= 0 && c != '\n')
    {
    }
  }

  // Stream the page in chunks: the file's text is never held in RAM whole.
  webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
  sendSafe(200, "text/html", "");
  String head = pageHead("View / Edit File", htmlEsc(name).c_str(), "files", "file", false);
  head += "<div class='card'>";
  head += "<div class='crumbs'><span class='badge'><i class='ic ic-database'></i>" + formatSize(size) + "</span>";
  head += editable ? "<span class='badge badge-ok'>Editable</span>" : "<span class='badge badge-warn'>Read-only</span>";
  head += "</div>";
  if (editable)
  {
    head += "<form method='POST' action='/files/save'>";
    head += "<input type='hidden' name='name' value='" + htmlEsc(name) + "'>";
  }
  else
  {
    head += alertHtml("info", "This file is too large to edit here (limit " + formatSize(FILE_EDIT_MAX_BYTES) + ")." +
                                  (tailOnly ? String(" Showing only the last ") + formatSize(FILE_VIEW_MAX_BYTES) + "." : String("")) +
                                  " Use Download to get the whole file.");
  }
  head += "<textarea class='code' name='content' rows='22' maxlength='" + String(FILE_EDIT_MAX_BYTES) + "' spellcheck='false' " +
          (editable ? "" : "readonly ") + ">\n"; // first newline is ignored by the browser
  webServer.sendContent(head);

  uint8_t buf[512];
  int n;
  while ((n = f.read(buf, sizeof(buf))) > 0)
  {
    String chunk;
    chunk.reserve(n + 32);
    for (int i = 0; i < n; i++)
    {
      char c = (char)buf[i];
      if (c == '&')
        chunk += "&amp;";
      else if (c == '<')
        chunk += "&lt;";
      else if (c == '>')
        chunk += "&gt;";
      else
        chunk += c;
    }
    webServer.sendContent(chunk);
  }
  f.close();

  String tail = "</textarea>";
  tail += "<div class='form-actions'>";
  if (editable)
    tail += "<button type='submit' class='btn btn-primary'><i class='ic ic-check'></i>Save changes</button>";
  tail += "<a href='/files/download?name=" + urlEnc(name) + "' class='btn btn-outline'><i class='ic ic-download'></i>Download</a>";
  tail += backButton(filesTabUrl(name));
  tail += "</div>";
  tail += editable ? "</form></div>" : "</div>";
  tail += pageFoot();
  webServer.sendContent(tail);
  webServer.sendContent("");
}

static void handleFileSavePost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  String content = webServer.arg("content");
  if (!validSdPath(name))
  {
    sendSafe(400, "text/html", errorPage("Invalid file name.", filesTabUrl(name).c_str()));
    return;
  }
  if (content.length() > FILE_EDIT_MAX_BYTES)
  {
    sendSafe(400, "text/html", errorPage("Content too large to save (limit " + formatSize(FILE_EDIT_MAX_BYTES) + ").", filesTabUrl(name).c_str()));
    return;
  }
  content.replace("\r", ""); // browsers submit textarea line breaks as CRLF
  File f;
  if (!sdOpen("/" + name, FILE_WRITE, f)) // FILE_WRITE truncates, i.e. replaces the file
  {
    sendSafe(500, "text/html", errorPage("Could not write the file. Check the SD card.", filesTabUrl(name).c_str()));
    return;
  }
  f.print(content);
  f.close();
  Serial.printf("Web: file saved — %s (%u bytes)\n", name.c_str(), (unsigned)content.length());
  webServer.sendHeader("Location", filesTabUrl(name).c_str());
  sendSafe(303);
}

static void handleFileConfirmDelete()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  if (!validSdPath(name) || !SD.exists("/" + name))
  {
    sendSafe(404, "text/html", errorPage("File not found.", filesTabUrl(name).c_str()));
    return;
  }
  String html = pageHead("Delete File", nullptr, "files");
  html += confirmDeleteCard("/files/delete", "name", htmlEsc(name), htmlEsc(name), filesTabUrl(name), "file");
  html += pageFoot();
  sendSafe(200, "text/html", html);
}

static void handleFileDeletePost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  if (!validSdPath(name) || !SD.remove("/" + name))
  {
    sendSafe(404, "text/html", errorPage("Could not delete the file.", filesTabUrl(name).c_str()));
    return;
  }
  Serial.printf("Web: file deleted — %s\n", name.c_str());
  webServer.sendHeader("Location", filesTabUrl(name).c_str());
  sendSafe(303);
}

static void handleFileNewPost()
{
  if (!webAuthAdmin())
    return;
  String name = webServer.arg("name");
  name.trim();
  if (name.indexOf('.') < 0)
    name += ".txt";
  if (!validSdName(name))
  {
    sendSafe(400, "text/html", errorPage("Invalid file name. Use up to 60 characters and avoid / \\ : * ? \" &lt; &gt; |.", "/?tab=files"));
    return;
  }
  if (SD.exists("/" + name))
  {
    sendSafe(400, "text/html", errorPage("A file with that name already exists.", "/?tab=files"));
    return;
  }
  File f;
  if (!sdOpen("/" + name, FILE_WRITE, f))
  {
    sendSafe(500, "text/html", errorPage("Could not create the file. Check the SD card.", "/?tab=files"));
    return;
  }
  f.close();
  Serial.printf("Web: file created — %s\n", name.c_str());
  webServer.sendHeader("Location", "/files/edit?name=" + urlEnc(name));
  sendSafe(303);
}

// ============================================================
//  Static CSS  (GET /style.css — cached by browser for 24 h)
// ============================================================
static void handleStyleCSS()
{
  // The ETag is CSS_VER (see HTML_STYLE), so a changed stylesheet drops the cached copy.
  webServer.sendHeader("Cache-Control", "public, max-age=86400");
  webServer.sendHeader("ETag", "\"v" CSS_VER "\"");
  if (webServer.header("If-None-Match") == "\"v" CSS_VER "\"")
  {
    sendSafe(304);
    return;
  }
  sendSafeP(200, "text/css", HTML_STYLE);
}

// ============================================================
//  Logo  (GET /logo.png — streamed from flash, cached by browser)
// ============================================================
// Public like /style.css: the sign-in page shows it before anyone is logged in.
// The ETag is LOGO_VER; bump it whenever src/web_logo.h is regenerated.
static void handleLogoPNG()
{
  webServer.sendHeader("Cache-Control", "public, max-age=86400");
  webServer.sendHeader("ETag", "\"logo" LOGO_VER "\"");
  if (webServer.header("If-None-Match") == "\"logo" LOGO_VER "\"")
  {
    sendSafe(304);
    return;
  }
  sendSafeP(200, "image/png", (const char *)WEB_LOGO_PNG, WEB_LOGO_PNG_LEN);
}

void setupWebRoutes()
{
  loadWebAdmin();
  loadDevices();
  const char *hdrs[] = {"Cookie", "If-None-Match", "X-Requested-With"};
  webServer.collectHeaders(hdrs, 3);
  webServer.on("/style.css", HTTP_GET, handleStyleCSS);
  webServer.on("/logo.png", HTTP_GET, handleLogoPNG);
  webServer.on("/login", HTTP_GET, handleLoginGet);
  webServer.on("/login", HTTP_POST, handleLoginPost);
  webServer.on("/logout", HTTP_GET, handleLogout);
  webServer.on("/", HTTP_GET, handleRoot);
  webServer.on("/add", HTTP_GET, handleAddGet);
  webServer.on("/add", HTTP_POST, handleAddPost);
  webServer.on("/edit", HTTP_GET, handleEditGet);
  webServer.on("/edit", HTTP_POST, handleEditPost);
  webServer.on("/confirm-delete", HTTP_GET, handleConfirmDelete);
  webServer.on("/delete", HTTP_POST, handleDeletePost);
  webServer.on("/account", HTTP_GET, handleAccountGet);
  webServer.on("/account", HTTP_POST, handleAccountPost);
  webServer.on("/login-as", HTTP_GET, handleLoginAs);
  webServer.on("/motion/status", HTTP_GET, handleMotionStatus);
  webServer.on("/outconfig", HTTP_POST, handleOutConfigPost);
  webServer.on("/inconfig", HTTP_POST, handleInConfigPost);
  webServer.on("/netconfig", HTTP_POST, handleNetConfigPost);
  webServer.on("/timeconfig", HTTP_POST, handleTimeConfigPost);
  webServer.on("/devices", HTTP_POST, handleDevicesPost);
  webServer.on("/devices/delete", HTTP_POST, handleDeleteDevicePost);
  webServer.on("/cloud", HTTP_POST, handleCloudPost);
  webServer.on("/cloud/clear", HTTP_POST, handleCloudClearPost);
  webServer.on("/firebase", HTTP_POST, handleFirebasePost);
  webServer.on("/firebase/clear", HTTP_POST, handleFirebaseClearPost);
  webServer.on("/ota", HTTP_POST, handleOtaComplete, handleOtaUpload);
  webServer.on("/files/download", HTTP_GET, handleFileDownload);
  webServer.on("/files/edit", HTTP_GET, handleFileEditGet);
  webServer.on("/files/save", HTTP_POST, handleFileSavePost);
  webServer.on("/files/confirm-delete", HTTP_GET, handleFileConfirmDelete);
  webServer.on("/files/delete", HTTP_POST, handleFileDeletePost);
  webServer.on("/files/new", HTTP_POST, handleFileNewPost);
  webServer.onNotFound([]()
                       {
    Serial.printf("Web: 404 — no route for %s %s\n", webServer.method() == HTTP_POST ? "POST" : "GET", webServer.uri().c_str());
    sendSafe(404, "text/plain", "Not found"); });
  webServer.begin();
  Serial.println("Web server started");
}
