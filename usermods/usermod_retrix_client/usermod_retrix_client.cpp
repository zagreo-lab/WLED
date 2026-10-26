// usermod_retrix_client.cpp

//#pragma once
#include "wled.h"
//#include <ArduinoWebsockets.h>
#include <WiFiClient.h>
#include "NuSock.h"



class WledRetrixClientUsermod : public Usermod {
  private:
    WiFiClient tcpClient;          // trasporto TCP sottostante
    NuSockClient wsClient;         // wrapper WebSocket di NuSock
    bool isConnected = false;
    unsigned long lastReconnectAttempt = 0;

    // Configurazione (modificabile da UI WLED)
    bool wssEnabled = false;
    String wssServer = "alexa.amfid.ch";
    int wssPort = 80;
    String wssPath = "/wled-ws";

    void onWsEvent(NuClient* client, NuClientEvent event,
                   const uint8_t* payload, size_t length) {
      switch (event) {
        case CLIENT_EVENT_CONNECTED:
          Serial.println("[Retrix] WebSocket connesso");
          isConnected = true;
          {
            String initMsg = "{\"event\":\"boot\",\"mac\":\"" + WiFi.macAddress() + "\"}";
            wsClient.send(initMsg.c_str());
            Serial.printf("[Retrix] Inviato: %s\n", initMsg.c_str());
          }
          break;

        case CLIENT_EVENT_DISCONNECTED:
          Serial.println("[Retrix] WebSocket disconnesso");
          isConnected = false;
          break;

        case CLIENT_EVENT_TEXT:
          Serial.printf("[Retrix] Ricevuto: %.*s\n", (int)length, (const char*)payload);
          // Per ora solo log; in futuro: deserializeState(...)
          break;

        case CLIENT_EVENT_ERROR:
          Serial.println("[Retrix] Errore WebSocket");
          break;

        default:
          break;
      }
    }
    

  public:
    void setup() override {

      Serial.println("[Retrix] Usermod setup");

      if (!wssEnabled) {
        Serial.println("[Retrix] Client disabilitato da config");
        return;
      }
      if (wssServer.length() == 0) {
        Serial.println("[Retrix] Server non configurato");
        return;
      }

      // Registra i callback
      wsClient.onEvent(onWsEvent);

      Serial.printf("[Retrix] Connessione a ws://%s:%d%s\n", wssServer.c_str(), wssPort, wssPath.c_str());
      /*
      // Connessione in chiaro (ws://) per il test iniziale
      webSocket.begin(wssServer.c_str(), wssPort, wssPath.c_str());

      webSocket.onEvent([this](WStype_t type, uint8_t * payload, size_t length) {
        this->webSocketEvent(type, payload, length);
      });

      webSocket.setReconnectInterval(5000);

      // Opzionale: heartbeat per capire se il canale è vivo
      webSocket.enableHeartbeat(15000, 3000, 2);
      */

      // Avvia la connessione utilizzando il client TCP
      wsClient.begin(tcpClient, wssServer.c_str(), wssPort, wssPath.c_str());

    }

    void loop() override {
      if (!wssEnabled) return;
      //webSocket.loop();
      / NuSock richiede il polling nel loop
      wsClient.loop();
    }

    void addToConfig(JsonObject& root) override {
      JsonObject top = root.createNestedObject("Retrix Cloud Client");
      top["Abilitato"] = wssEnabled;
      top["Server Cloud (Host)"] = wssServer;
      top["Porta Server"] = wssPort;
      top["WebSocket Path"] = wssPath;
    }

    bool readFromConfig(JsonObject& root) override {
      //JsonObject top = root["Retrix Cloud Client"];
      //if (top.isNull()) return false;

      //wssEnabled = top["Abilitato"] | wssEnabled;
      //wssServer  = top["Server Cloud (Host)"] | wssServer;
      //wssPort    = top["Porta Server"] | wssPort;
      //wssPath    = top["WebSocket Path"] | wssPath;
      // Nota: qui si legge direttamente da root, non da un oggetto annidato
      if (root.isNull()) return false;
      wssEnabled = root["Abilitato"] | wssEnabled;
      wssServer  = root["Server Cloud (Host)"] | wssServer;
      wssPort    = root["Porta Server"] | wssPort;
      wssPath    = root["WebSocket Path"] | wssPath;

      return true;
    }

    // Identificativo e nome per l'array "um" di /json/info
    uint16_t getId() override {
      return 88;
    }

    // const char* getName() override {
    //  return "retrix_client";
    // }

};

// Autoregistrazione a livello di file scope (Metodo ufficiale v2)
static WledRetrixClientUsermod retrixCloudClient;
REGISTER_USERMOD(retrixCloudClient);
