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
// - quando il tunnel sale si annuncia a Retrix (POST /api/devices/announce sul server VPN),
//   così Retrix la registra subito invece di aspettare la propria discovery.
//
// Non compilare insieme all'usermod "wireguard": includono la stessa libreria.

#include "wled.h"
#include "WireGuard-ESP32.h"

#include <time.h>
#include <HTTPClient.h>

namespace {

constexpr unsigned long kCheckInterval   = 5000UL;    // controllo dello stato
constexpr unsigned long kRetryInterval   = 30000UL;   // dopo un begin() fallito
constexpr unsigned long kHandshakeWindow = 180000UL;  // senza handshake per tanto: ricrea il tunnel
constexpr time_t        kValidEpoch      = 1700000000; // ora considerata sincronizzata (nov 2023)
constexpr unsigned long kAnnounceRetry   = 30000UL;   // primo nuovo tentativo; poi raddoppia
constexpr uint8_t       kAnnounceMax     = 4;         // tentativi totali per ogni salita del link
constexpr uint16_t      kAnnounceTimeout = 3000;      // ms, connessione e risposta dell'annuncio

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
    bool      announce      = true;   // annuncio a Retrix quando il tunnel sale
    int       announcePort  = 3004;   // porta di Retrix sul server VPN

    // Stato
    bool          timeStarted   = false;
    bool          reconfigure   = false;
    unsigned long lastCheck     = 0;
    unsigned long nextAttempt   = 0;
    unsigned long lastLinkUp    = 0;   // ultima volta che il link risultava attivo
    bool          wasUp         = false; // stato del link al controllo precedente
    time_t        upSince       = 0;     // ora (UTC, epoch) in cui il link è salito

    // Annuncio a Retrix
    bool          announcePending  = false;  // annuncio da inviare (link appena salito)
    uint8_t       announceAttempts = 0;      // tentativi fatti dall'ultima salita del link
    unsigned long nextAnnounce     = 0;
    volatile bool announceBusy     = false;  // richiesta in corso nel task
    volatile int  announceResult   = 0;      // esito dal task: 0 nessuno, <0 errore di rete
    int           lastAnnounceCode = 0;      // ultimo esito, per /json/info
    char          announceUrl[64]  = "";

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
      announcePending = false;
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

    // Retrix gira sul server WireGuard: il primo indirizzo della rete VPN (es. 10.8.0.1)
    IPAddress serverVpnIp() const {
      return IPAddress(localIp[0] & vpnMask[0], localIp[1] & vpnMask[1],
                       localIp[2] & vpnMask[2], (localIp[3] & vpnMask[3]) + 1);
    }

    void startAnnounce(unsigned long now) {
      snprintf(announceUrl, sizeof(announceUrl), "http://%s:%d/api/devices/announce",
               serverVpnIp().toString().c_str(), announcePort);
      announceResult = 0;
      announceBusy = true;
      // Task separato: la richiesta può durare secondi e non deve fermare il loop di WLED
      if (xTaskCreate(announceTask, "wg_announce", 4096, this, 1, nullptr) != pdPASS) {
        announceBusy = false;
        nextAnnounce = now + kAnnounceRetry;
      }
    }

    static void announceTask(void* arg) {
      UsermodRetrixWG* self = static_cast<UsermodRetrixWG*>(arg);
      int code = -1;
      {
        HTTPClient http;
        http.setConnectTimeout(kAnnounceTimeout);
        http.setTimeout(kAnnounceTimeout);
        if (http.begin(self->announceUrl)) {
          http.addHeader("Content-Type", "application/json");
          code = http.POST("{}");   // Retrix usa l'IP sorgente, il contenuto non serve
          http.end();
        }
      } // HTTPClient distrutto prima di chiudere il task
      self->announceResult = code;
      self->announceBusy = false;
      vTaskDelete(nullptr);
    }

    void handleAnnounceResult(unsigned long now) {
      if (announceBusy || announceResult == 0) return;
      lastAnnounceCode = announceResult;
      announceResult = 0;
      DEBUG_PRINTF("[WireGuard] annuncio a Retrix: %d\n", lastAnnounceCode);

      // 200 registrata; 403/404 Retrix non accetta annunci da qui: inutile ripetere.
      // Altro (Retrix non ancora avviato, 502, errore di rete): nuovo tentativo.
      if (lastAnnounceCode == 200 || lastAnnounceCode == 403 || lastAnnounceCode == 404) {
        announcePending = false;
        return;
      }

      // Retrix non ancora avviato, 502, errore di rete: nuovo tentativo con intervallo
      // crescente (30 s, 60 s, 120 s). Dopo kAnnounceMax si smette: la matrice verrà
      // comunque trovata dalla discovery periodica di Retrix.
      if (++announceAttempts >= kAnnounceMax) {
        announcePending = false;
        DEBUG_PRINTLN(F("[WireGuard] annuncio a Retrix non riuscito, rinuncio"));
      } else {
        nextAnnounce = now + (kAnnounceRetry << (announceAttempts - 1));
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
        if (!wasUp) {
          upSince = time(nullptr);     // il link è appena salito
          announcePending = announce;  // ...e Retrix va avvisato
          announceAttempts = 0;
          nextAnnounce = now;
        }
        lastLinkUp = now;

        handleAnnounceResult(now);
        if (announcePending && !announceBusy && (long)(now - nextAnnounce) >= 0) {
          startAnnounce(now);
        }
      } else {
        upSince = 0;
        if (now - lastLinkUp > kHandshakeWindow) {
          // Nessun handshake da troppo tempo: forse è cambiato l'IP del server (DNS dinamico).
          DEBUG_PRINTLN(F("[WireGuard] nessun handshake, ricreo il tunnel"));
          stopTunnel();               // azzera anche wasUp, upSince e announcePending
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
      wgState[F("announce")] = lastAnnounceCode;   // 0 nessuno, 200 ok, <0 errore di rete
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
      s.print(F("addInfo('WireGuard:announce',1,'Announce to Retrix');"));
      s.print(F("addInfo('WireGuard:announce_port',1,'Retrix port');"));
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
      top["announce"]      = announce;
      top["announce_port"] = announcePort;
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

      // Annuncio: non richiede di ricreare il tunnel (non entra in "changed")
      announce     = top["announce"] | announce;
      announcePort = top["announce_port"] | announcePort;

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