// usermod_asyncWSClient.cpp

// usermod_asyncWSClient.cpp
//
// Retrix Cloud Client: client WebSocket in uscita (ws://, senza TLS) verso il server Retrix.
// La matrice apre la connessione, quindi non servono port forwarding né l'API di WLED esposta.
//
// Protocollo (provvisorio, SENZA autenticazione: usare solo per prove su reti fidate):
//   matrice -> server  {"t":"hello","id":"<MAC>","name":"...","ver":"..."}   all'apertura
//   matrice -> server  {"t":"state","on":true,"bri":128}                    ogni RETRIX_WS_STATUS_INTERVAL ms
//   server  -> matrice stato WLED in JSON (stesso formato di POST /json/state), oppure "ON" / "OFF"
//
// Nota sui thread: i callback di AsyncTCP girano nel task di rete. Qui servono solo a
// leggere i dati e a rispondere a ping/chiusura; i messaggi ricevuti vengono messi in
// coda e applicati a WLED da loop(), nel task principale.
//
// Compilazione: se alcune chiamate interne di WLED non esistono nella tua versione
// (requestJSONBufferLock / pDoc / deserializeState), definisci -D RETRIX_WS_ONLY_ONOFF
// per usare solo i comandi "ON"/"OFF" come nella versione originale.

#include "wled.h"
#include <AsyncTCP.h>

#include "retrix_ws_codec.h"

#ifndef RETRIX_WS_STATUS_INTERVAL
#define RETRIX_WS_STATUS_INTERVAL 5000UL
#endif

#define USERMOD_ID_RETRIX_WS_CLIENT 200   

namespace {

constexpr unsigned long kConnectTimeout   = 10000UL;   // TCP + DNS
constexpr unsigned long kHandshakeTimeout = 8000UL;    // attesa della risposta 101
constexpr unsigned long kStatusInterval   = RETRIX_WS_STATUS_INTERVAL;
constexpr unsigned long kBackoffMin       = 2000UL;    // tra un tentativo e il successivo
constexpr unsigned long kBackoffMax       = 60000UL;
constexpr uint8_t       kBufferLockId     = 21;        // id (solo diagnostico) per requestJSONBufferLock

// WLED dichiara alcune globali come char[] e altre come String: gli overload le accettano entrambe.
const char* cstr(const char* s)   { return s; }
const char* cstr(const String& s) { return s.c_str(); }

std::string trimCopy(const char* s) {
  std::string r = s ? s : "";
  const char* ws = " \t\r\n";
  const size_t b = r.find_first_not_of(ws);
  if (b == std::string::npos) return "";
  return r.substr(b, r.find_last_not_of(ws) - b + 1);
}

}  // namespace

class UsermodAsyncWSClient : public Usermod, public retrix::WsSink {
private:
  enum class Link : uint8_t { IDLE, CONNECTING, HANDSHAKE, OPEN };

  AsyncClient* _client = nullptr;
  retrix::WsCodec _codec;

  volatile Link _link = Link::IDLE;
  unsigned long _stateSince = 0;
  unsigned long _nextAttempt = 0;
  unsigned long _backoff = kBackoffMin;
  unsigned long _lastStatus = 0;
  bool _wasOpen = false;
  bool _reconfigure = false;
  bool _configLoaded = false;

  // Ultimo messaggio ricevuto in attesa di essere applicato (latest-wins).
  char* _pending = nullptr;
  portMUX_TYPE _mux = portMUX_INITIALIZER_UNLOCKED;

  // Configurazione (modificabile dalla UI di WLED). Disabilitato di default.
  bool   wssEnabled = false;
  String wssServer  = "";
  int    wssPort    = 80;
  String wssPath    = "/wled-ws";

  // ---------------------------------------------------------------- connessione

  void ensureClient() {
    if (_client) return;
    _client = new AsyncClient();

    _client->onConnect([this](void*, AsyncClient* c) { onTcpConnect(c); }, nullptr);
    _client->onData([this](void*, AsyncClient*, void* d, size_t l) { _codec.feed((const uint8_t*)d, l, *this); }, nullptr);
    _client->onDisconnect([this](void*, AsyncClient*) { linkDown("disconnected"); }, nullptr);
    _client->onError([this](void*, AsyncClient*, int8_t) { linkDown("error"); }, nullptr);
    _client->onTimeout([this](void*, AsyncClient* c, uint32_t) { c->close(true); }, nullptr);
  }

  void startConnect(unsigned long now) {
    ensureClient();
    _link = Link::CONNECTING;
    _stateSince = now;
    DEBUG_PRINTF("[RetrixWS] connecting to %s:%d\n", wssServer.c_str(), wssPort);

    if (!_client->connect(wssServer.c_str(), (uint16_t)wssPort)) {
      linkDown("connect() failed");
    }
  }

  void onTcpConnect(AsyncClient* c) {
    _link = Link::HANDSHAKE;
    _stateSince = millis();
    _codec.reset();

    uint8_t key[16];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)esp_random();

    const std::string req = retrix::buildHandshakeRequest(
        wssServer.c_str(), (uint16_t)wssPort, wssPath.c_str(), retrix::base64Encode(key, sizeof(key)));
    c->write(req.c_str(), req.size());
  }

  // Connessione caduta o fallita: pianifica il prossimo tentativo (una sola volta per evento).
  void linkDown(const char* why) {
    if (_link == Link::IDLE) return;
    _link = Link::IDLE;
    DEBUG_PRINTF("[RetrixWS] link down: %s\n", why);

    if (_wasOpen) {                               // era connessa: riprova presto
      _backoff = kBackoffMin;
      _wasOpen = false;
    } else if (_backoff < kBackoffMax) {          // non è mai arrivata ad aprirsi: rallenta
      _backoff = (_backoff * 2 > kBackoffMax) ? kBackoffMax : _backoff * 2;
    }
    _nextAttempt = millis() + _backoff + (unsigned long)random(0, (long)(_backoff / 4) + 1);
  }

  // Timeout: pianifica il retry come per una connessione fallita e poi chiude il socket
  // (l'eventuale callback di disconnessione trova già lo stato IDLE e non fa nulla).
  void abortLink(const char* why) {
    if (_link == Link::IDLE) return;
    AsyncClient* c = _client;
    linkDown(why);
    if (c) c->close(true);
  }

  // Chiude subito senza pianificare il retry (usata da loop() quando si cambia configurazione).
  void dropLink() {
    if (_link == Link::IDLE) return;
    if (_link == Link::OPEN) {                      // chiusura regolare: il server sa che è voluta
      const uint8_t pl[2] = { 0x03, 0xE8 };         // 1000
      sendFrame(0x08, pl, 2);
    }
    _link = Link::IDLE;
    _wasOpen = false;
    if (_client) _client->close(true);
  }

  // ---------------------------------------------------------------- invio

  bool sendFrame(uint8_t opcode, const uint8_t* payload, size_t len) {
    if (!_client || _link != Link::OPEN) return false;

    uint8_t buf[300];
    const size_t n = retrix::buildClientFrame(opcode, payload, len, esp_random(), buf, sizeof(buf));
    if (n == 0 || !_client->canSend() || _client->space() < n) return false;
    return _client->write((const char*)buf, n) == n;
  }

  void sendJson(const char* json) { sendFrame(0x01, (const uint8_t*)json, strlen(json)); }

  void sendHello() {
    char mac[16] = {0};
    const char* m = cstr(escapedMac);
    for (size_t i = 0; i < sizeof(mac) - 1 && m[i]; i++) mac[i] = (char)toupper((unsigned char)m[i]);

    const std::string name = retrix::jsonEscape(cstr(serverDescription));
    const std::string ver  = retrix::jsonEscape(cstr(versionString));

    char buf[256];
    const int n = snprintf(buf, sizeof(buf), "{\"t\":\"hello\",\"id\":\"%s\",\"name\":\"%s\",\"ver\":\"%s\"}",
                           mac, name.c_str(), ver.c_str());
    if (n > 0 && n < (int)sizeof(buf)) sendJson(buf);
  }

  void sendStatus() {
    char buf[64];
    snprintf(buf, sizeof(buf), "{\"t\":\"state\",\"on\":%s,\"bri\":%u}", bri > 0 ? "true" : "false", (unsigned)bri);
    sendJson(buf);
  }

  // ---------------------------------------------------------------- ricezione (task di rete)

  void onOpen() override {
    _link = Link::OPEN;
    _wasOpen = true;
    _backoff = kBackoffMin;
    _lastStatus = millis();
    DEBUG_PRINTLN(F("[RetrixWS] connected"));
    sendHello();
  }

  void onText(const char* msg, size_t len) override {
    char* copy = (char*)malloc(len + 1);
    if (!copy) return;
    memcpy(copy, msg, len);
    copy[len] = '\0';

    portENTER_CRITICAL(&_mux);
    char* old = _pending;
    _pending = copy;                 // se il precedente non è ancora stato applicato, vince il più recente
    portEXIT_CRITICAL(&_mux);
    free(old);
  }

  void onPing(const uint8_t* payload, size_t len) override {
    sendFrame(0x0A, payload, len);
  }

  void onClose(uint16_t code) override {
    DEBUG_PRINTF("[RetrixWS] server closed (%u)\n", (unsigned)code);
    if (code == 1005) {
      sendFrame(0x08, nullptr, 0);
    } else {
      const uint8_t pl[2] = { (uint8_t)(code >> 8), (uint8_t)(code & 0xFF) };
      sendFrame(0x08, pl, 2);
    }
    if (_client) _client->close();
  }

  void onError(const char* reason, uint16_t closeCode) override {
    DEBUG_PRINTF("[RetrixWS] protocol error: %s\n", reason);
    if (closeCode) {
      const uint8_t pl[2] = { (uint8_t)(closeCode >> 8), (uint8_t)(closeCode & 0xFF) };
      sendFrame(0x08, pl, 2);
    }
    if (_client) _client->close(true);
  }

  // ---------------------------------------------------------------- applicazione dello stato (task principale)

  void applyMessage(const char* msg) {
#ifdef RETRIX_WS_ONLY_ONOFF
    if (!strcmp(msg, "ON")) {
      bri = briLast;
      colorUpdated(CALL_MODE_DIRECT_CHANGE);
    } else if (!strcmp(msg, "OFF")) {
      briLast = bri;
      bri = 0;
      colorUpdated(CALL_MODE_DIRECT_CHANGE);
    }
#else
    if (!strcmp(msg, "ON"))  msg = "{\"on\":true}";
    if (!strcmp(msg, "OFF")) msg = "{\"on\":false}";

    if (!requestJSONBufferLock(kBufferLockId)) {
      DEBUG_PRINTLN(F("[RetrixWS] JSON buffer busy, message dropped"));
      return;
    }

    DeserializationError err = deserializeJson(*pDoc, msg);
    JsonObject root = pDoc->as<JsonObject>();
    if (!err && !root.isNull()) deserializeState(root);
    releaseJSONBufferLock();
#endif
  }

public:
  // Invia un messaggio di testo al server (max ~290 byte). false se non connessa o senza spazio.
  bool sendText(const String& message) {
    return sendFrame(0x01, (const uint8_t*)message.c_str(), message.length());
  }

  void setup() override {}

  // Chiamato da WLED quando il Wi-Fi si (ri)connette.
  void connected() override {
    _backoff = kBackoffMin;
    _nextAttempt = millis();
  }

  void loop() override {
    const unsigned long now = millis();

    // 1) applica l'ultimo messaggio ricevuto
    char* msg = nullptr;
    portENTER_CRITICAL(&_mux);
    msg = _pending;
    _pending = nullptr;
    portEXIT_CRITICAL(&_mux);
    if (msg) {
      applyMessage(msg);
      free(msg);
    }

    // 2) disabilitato o riconfigurato
    if (!wssEnabled || wssServer.length() == 0) {
      dropLink();
      return;
    }
    if (_reconfigure) {
      _reconfigure = false;
      dropLink();
      _backoff = kBackoffMin;
      _nextAttempt = now;
    }

    // 3) stato della connessione
    switch ((Link)_link) {
      case Link::IDLE:
        if (WLED_CONNECTED && (long)(now - _nextAttempt) >= 0) startConnect(now);
        break;

      case Link::CONNECTING:
        if (now - _stateSince > kConnectTimeout) abortLink("connect timeout");
        break;

      case Link::HANDSHAKE:
        if (now - _stateSince > kHandshakeTimeout) abortLink("handshake timeout");
        break;

      case Link::OPEN:
        if (now - _lastStatus >= kStatusInterval) {
          _lastStatus = now;
          sendStatus();
        }
        break;
    }
  }

  // ---------------------------------------------------------------- configurazione (UI di WLED)

  void addToConfig(JsonObject& root) override {
    JsonObject top = root.createNestedObject("Retrix Cloud Client");
    top["enabled"] = wssEnabled;
    top["host"]    = wssServer;
    top["port"]    = wssPort;
    top["path"]    = wssPath;
  }

  bool readFromConfig(JsonObject& root) override {
    // A seconda della versione di WLED l'oggetto è già quello del usermod oppure lo contiene.
    JsonObject nested = root["Retrix Cloud Client"];
    JsonObject top = nested.isNull() ? root : nested;
    if (top.isNull()) return false;

    bool complete = true;
    bool enabled = wssEnabled;
    int port = wssPort;
    std::string host = trimCopy(cstr(wssServer));
    std::string path = trimCopy(cstr(wssPath));

    if (top["enabled"].is<bool>())        enabled = top["enabled"];                       else complete = false;
    if (top["host"].is<const char*>())    host = trimCopy(top["host"].as<const char*>()); else complete = false;
    if (top["port"].is<int>())            port = top["port"];                             else complete = false;
    if (top["path"].is<const char*>())    path = trimCopy(top["path"].as<const char*>()); else complete = false;

    if (port < 1 || port > 65535) port = 80;
    if (path.empty() || path[0] != '/') path = "/" + path;

    const bool changed = enabled != wssEnabled || port != wssPort ||
                         host != cstr(wssServer) || path != cstr(wssPath);

    wssEnabled = enabled;
    wssPort    = port;
    wssServer  = host.c_str();
    wssPath    = path.c_str();

    if (_configLoaded && changed) _reconfigure = true;   // riconnessione con i nuovi parametri
    _configLoaded = true;
    return complete;                                     // false: WLED riscrive i valori di default
  }

  uint16_t getId() override {
    return USERMOD_ID_RETRIX_WS_CLIENT;
  }
};

static UsermodAsyncWSClient retrixCloudClient;
REGISTER_USERMOD(retrixCloudClient);