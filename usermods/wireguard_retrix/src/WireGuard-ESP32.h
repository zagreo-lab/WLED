/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

class WireGuard
{
private:
    bool _is_initialized = false;

public:
    // allowedIP/allowedMask: rete instradata nel tunnel (0.0.0.0/0 = tutto il traffico).
    // setAsDefault: il tunnel diventa l'interfaccia di default (serve solo con 0.0.0.0/0).
    bool begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey,
               const IPAddress &allowedIP, const IPAddress &allowedMask, bool setAsDefault);
    bool begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey = NULL);
    bool begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey = NULL);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
    // true dopo un handshake riuscito con il server (finché la sessione resta valida)
    bool is_link_up() const;
};
