// usermod_retrix_client.cpp

#pragma once
#include "wled.h"
#include <WebSocketsClient.h>



class WledRetrixClientUsermod : public Usermod {
  private:
    WebSocketsClient webSocket;
    bool isConnected = false;
    unsigned long lastReconnectAttempt = 0;

    
    bool wssEnabled = false;
    String wssServer = "alexa.amfid.ch";
    int wssPort = 80;
    String wssPath = "/wled-ws";

    void webSocketEvent(WStype_t type, uint8_t * payload, size_t length) {
      switch(type) {
        case WStype_DISCONNECTED:
          Serial.println("[Retrix] WebSocket disconnesso");
          isConnected = false;
          break;
        case WStype_CONNECTED:
          Serial.printf("[Retrix] WebSocket connesso a %s:%d%s\n",wssServer.c_str(), wssPort, wssPath.c_str());
          isConnected = true;
          {
            // Messaggio di presentazione al server
            String initMsg = "{\"event\":\"boot\",\"mac\":\"" + WiFi.macAddress() + "\"}";
            webSocket.sendTXT(initMsg);
            Serial.printf("[Retrix] Inviato: %s\n", initMsg.c_str());
          }
          break;
        case WStype_TEXT:
          Serial.printf("[Retrix] Ricevuto (%u byte): %.*s\n", (unsigned)length, (int)length, (const char*)payload);
          //if (length > 0) {
          //  deserializeState(payload, CALL_MODE_WS_SEND);
          //}
          break;

        case WStype_ERROR:
          Serial.println("[Retrix] Errore WebSocket");
          break;

        case WStype_PING:
          Serial.println("[Retrix] Ping ricevuto");
          break;

        case WStype_PONG:
          Serial.println("[Retrix] Pong ricevuto");
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

      Serial.printf("[Retrix] Connessione a ws://%s:%d%s\n", wssServer.c_str(), wssPort, wssPath.c_str());

      // Connessione in chiaro (ws://) per il test iniziale
      webSocket.begin(wssServer.c_str(), wssPort, wssPath.c_str());

      webSocket.onEvent([this](WStype_t type, uint8_t * payload, size_t length) {
        this->webSocketEvent(type, payload, length);
      });

      webSocket.setReconnectInterval(5000);

      // Opzionale: heartbeat per capire se il canale è vivo
      webSocket.enableHeartbeat(15000, 3000, 2);

    }

    void loop() override {
      if (!wssEnabled) return;
      webSocket.loop();
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
