// usermod_retrix_wg.cpp
//
// Client WireGuard per collegare la matrice a Retrix attraverso una VPN.
// Deriva dall'usermod "wireguard" di WLED (Aiden Vigue) con queste differenze:
// - split tunnel: nel tunnel passa solo la rete VPN (es. 10.8.0.0/24), il resto esce dal Wi-Fi;
//   "full tunnel" ripristina il comportamento originale (tutto il traffico nel tunnel);
// - interruttore "enabled" e maschera della rete VPN configurabili;
// - parsing dell'IP corretto (l'originale usava sscanf %u su uint8_t) e stringhe sempre terminate;
// - ora di sistema in UTC via SNTP (serve solo al timestamp dell'handshake), senza fuso POSIX;
// - se l'handshake non riesce per troppo tempo il tunnel viene ricreato (rilegge il DNS dell'host);
// - begin() non blocca il loop con i tentativi DNS: i nuovi tentativi sono distanziati.
// - Funziona anche con l’NTP di WLED disattivato.
//
// Non compilare insieme all'usermod "wireguard": includono la stessa libreria.

#include "wled.h"
#include "WireGuard-ESP32.h"

#include <time.h>

namespace {

constexpr unsigned long kCheckInterval   = 5000UL;    // controllo dello stato
constexpr unsigned long kRetryInterval   = 30000UL;   // dopo un begin() fallito
constexpr unsigned long kHandshakeWindow = 180000UL;  // senza handshake per tanto: ricrea il tunnel
constexpr time_t        kValidEpoch      = 1700000000; // ora considerata sincronizzata (nov 2023)

const char kName[]      = "WireGuard";
const char kFallbackNtp[] = "pool.ntp.org";

}  // namespace

class UsermodRetrixWG : public Usermod {
  private:
    WireGuard wg;

    // Configurazione
    bool      enabled       = false;
    bool      fullTunnel    = false;
    char      endpointHost[101] = "";
    int       endpointPort  = 51820;
    IPAddress localIp       = IPAddress(0, 0, 0, 0);
    IPAddress vpnMask       = IPAddress(255, 255, 255, 0);
    char      privateKey[45]   = "";
    char      publicKey[45]    = "";
    char      presharedKey[45] = "";

    // Stato
    bool          timeStarted   = false;
    bool          reconfigure   = false;
    unsigned long lastCheck     = 0;
    unsigned long nextAttempt   = 0;
    unsigned long lastLinkUp    = 0;   // ultima volta che il link risultava attivo
    bool          wasUp         = false; // stato del link al controllo precedente
    time_t        upSince       = 0;     // ora (UTC, epoch) in cui il link è salito

    bool configValid() const {
      return enabled && endpointHost[0] && endpointPort > 0 && endpointPort <= 65535 &&
             (uint32_t)localIp != 0 && strlen(privateKey) == 44 && strlen(publicKey) == 44;
    }

    bool timeValid() const { return time(nullptr) > kValidEpoch; }

    void startTime() {
      if (timeStarted) return;
      // UTC: l'ora serve solo al timestamp TAI64N dell'handshake.
      configTime(0, 0, ntpServerName[0] ? ntpServerName : kFallbackNtp, kFallbackNtp);
      timeStarted = true;
    }

    void stopTunnel() {
      wasUp   = false;
      upSince = 0;
      if (wg.is_initialized()) {
        wg.end();
        DEBUG_PRINTLN(F("[WireGuard] tunnel chiuso"));
      }
    }

    void startTunnel(unsigned long now) {
      // Split tunnel: rete VPN = IP locale & maschera. Full tunnel: tutto il traffico.
      const IPAddress net = IPAddress((uint32_t)localIp & (uint32_t)vpnMask);
      const IPAddress allowedIp   = fullTunnel ? IPAddress(0, 0, 0, 0) : net;
      const IPAddress allowedMask = fullTunnel ? IPAddress(0, 0, 0, 0) : vpnMask;

      DEBUG_PRINTF("[WireGuard] connessione a %s:%d\n", endpointHost, endpointPort);
      const bool ok = wg.begin(localIp, vpnMask, IPAddress(0, 0, 0, 0), privateKey, endpointHost, publicKey,
                               (uint16_t)endpointPort, presharedKey[0] ? presharedKey : nullptr,
                               allowedIp, allowedMask, fullTunnel);
      if (ok) {
        lastLinkUp = now;
      } else {
        DEBUG_PRINTLN(F("[WireGuard] avvio fallito (DNS o chiave non valida)"));
        nextAttempt = now + kRetryInterval;
      }
    }

    static void copyString(char* dest, size_t size, const char* src) {
      strlcpy(dest, src ? src : "", size);
    }

  public:
    void setup() override {}

    // Wi-Fi (ri)connesso: l'interfaccia sottostante può essere cambiata, il tunnel va ricreato.
    void connected() override {
      stopTunnel();
      nextAttempt = millis();
    }


    void loop() override {
      const unsigned long now = millis();
      if (now - lastCheck < kCheckInterval) return;
      lastCheck = now;

      if (reconfigure) {
        reconfigure = false;
        stopTunnel();
        nextAttempt = now;
      }

      if (!configValid()) {
        stopTunnel();
        return;
      }
      if (!WLED_CONNECTED) return;

      startTime();
      if (!timeValid()) return;   // senza ora corretta il server scarta l'handshake

      if (!wg.is_initialized()) {
        if ((long)(now - nextAttempt) >= 0) startTunnel(now);
        return;
      }

      const bool up = wg.is_link_up();
      if (up) {
        if (!wasUp) upSince = time(nullptr);   // il link è appena salito
        lastLinkUp = now;
      } else {
        upSince = 0;
        if (now - lastLinkUp > kHandshakeWindow) {
          // Nessun handshake da troppo tempo: forse è cambiato l'IP del server (DNS dinamico).
          DEBUG_PRINTLN(F("[WireGuard] nessun handshake, ricreo il tunnel"));
          stopTunnel();               // azzera anche wasUp e upSince
          nextAttempt = now;
          return;
        }
      }
      wasUp = up;
    }
    

    // Stato colorato nella pagina Info (il valore viene inserito come HTML)
    static String colored(const char* color, const String& text) {
      return String(F("<span style=\"color:")) + color + F("\">") + text + F("</span>");
    }

    void addToJsonInfo(JsonObject& root) override {
      JsonObject user = root["u"];
      if (user.isNull()) user = root.createNestedObject("u");
      JsonArray infoArr = user.createNestedArray(FPSTR(kName));

      if (!enabled)                 infoArr.add(colored("#f44", F("disabled")));
      else if (!configValid())      infoArr.add(colored("#f44", F("wrong configuration")));
      else if (!timeValid())        infoArr.add(colored("#fa0", F("waiting time (NTP)")));
      else if (wg.is_link_up())     infoArr.add(colored("#4c4", String(F("connected ")) + localIp.toString()));
      else if (wg.is_initialized()) infoArr.add(colored("#fa0", F("waiting handshake")));
      else                          infoArr.add(colored("#f44", F("not connected")));

      // Stato leggibile dalle macchine (Retrix): non compare nella pagina Info
      JsonObject wgState = root.createNestedObject(F("wg"));
      wgState[F("enabled")] = enabled;
      wgState[F("up")]      = wg.is_link_up();
      wgState[F("ip")]      = localIp.toString();
      wgState[F("since")]   = (uint32_t)upSince;   // epoch UTC; 0 se non connesso
    }

    void appendConfigData(Print& s) override {
      s.print(F("addInfo('WireGuard:host',1,'Server (host o IP)');"));
      s.print(F("addInfo('WireGuard:port',1,'Server UDP port');"));
      s.print(F("addInfo('WireGuard:ip',1,'IP within the VPN');"));
      s.print(F("addInfo('WireGuard:mask',1,'VPN network mask');"));
      s.print(F("addInfo('WireGuard:pem',1,'Device private key');"));
      s.print(F("addInfo('WireGuard:pub',1,'Server public key');"));
      s.print(F("addInfo('WireGuard:psk',1,'Pre-shared key');"));
      s.print(F("addInfo('WireGuard:full_tunnel',1,'All traffic in the VPN');"));
    }

    void addToConfig(JsonObject& root) override {
      JsonObject top = root.createNestedObject(FPSTR(kName));
      top["enabled"]     = enabled;
      top["host"]        = endpointHost;
      top["port"]        = endpointPort;
      top["ip"]          = localIp.toString();
      top["mask"]        = vpnMask.toString();
      top["pem"]         = privateKey;
      top["pub"]         = publicKey;
      top["psk"]         = presharedKey;
      top["full_tunnel"] = fullTunnel;
    }

    bool readFromConfig(JsonObject& root) override {
      JsonObject top = root[FPSTR(kName)];
      if (top.isNull()) return false;

      const bool      oldEnabled = enabled, oldFull = fullTunnel;
      const int       oldPort = endpointPort;
      const IPAddress oldIp = localIp, oldMask = vpnMask;
      char oldHost[sizeof(endpointHost)], oldPem[sizeof(privateKey)], oldPub[sizeof(publicKey)], oldPsk[sizeof(presharedKey)];
      memcpy(oldHost, endpointHost, sizeof(oldHost));
      memcpy(oldPem, privateKey, sizeof(oldPem));
      memcpy(oldPub, publicKey, sizeof(oldPub));
      memcpy(oldPsk, presharedKey, sizeof(oldPsk));

      bool complete = !top["enabled"].isNull() && !top["mask"].isNull() && !top["full_tunnel"].isNull();

      // Configurazioni dell'usermod originale (senza "enabled"): attivo se i campi ci sono.
      enabled    = top["enabled"] | (bool)(!top["host"].isNull() && !top["pem"].isNull());
      fullTunnel = top["full_tunnel"] | fullTunnel;
      endpointPort = top["port"] | endpointPort;
      copyString(endpointHost, sizeof(endpointHost), top["host"] | "");
      copyString(privateKey,   sizeof(privateKey),   top["pem"]  | "");
      copyString(publicKey,    sizeof(publicKey),    top["pub"]  | "");
      copyString(presharedKey, sizeof(presharedKey), top["psk"]  | "");

      IPAddress parsed;
      localIp = parsed.fromString((const char*)(top["ip"] | "")) ? parsed : IPAddress(0, 0, 0, 0);
      if (parsed.fromString((const char*)(top["mask"] | ""))) vpnMask = parsed;

      const bool changed = oldEnabled != enabled || oldFull != fullTunnel || oldPort != endpointPort ||
                           (uint32_t)oldIp != (uint32_t)localIp || (uint32_t)oldMask != (uint32_t)vpnMask ||
                           strcmp(oldHost, endpointHost) || strcmp(oldPem, privateKey) ||
                           strcmp(oldPub, publicKey) || strcmp(oldPsk, presharedKey);
      if (changed) reconfigure = true;

      return complete;
    }

    uint16_t getId() override { return USERMOD_ID_WIREGUARD; }
};

static UsermodRetrixWG usermodRetrixWG;
REGISTER_USERMOD(usermodRetrixWG);
