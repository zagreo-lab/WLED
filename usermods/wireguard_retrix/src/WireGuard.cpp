/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Modifiche per Retrix (usermod wireguard_retrix):
 * - rete instradata nel tunnel configurabile (split tunnel) invece di 0.0.0.0/0;
 * - il tunnel diventa l'interfaccia di default solo se richiesto;
 * - le chiamate lwIP (netif, peer, timer) girano nel thread tcpip tramite tcpip_api_call;
 * - is_link_up() per sapere se l'handshake con il server è avvenuto.
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h"

#include "esp32-hal-log.h"

extern "C"
{
#include "wireguardif.h"
#include "wireguard-platform.h"
}

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static struct netif *previous_default_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

#define TAG "[WireGuard] "

// Dati passati alle funzioni eseguite nel thread tcpip.
struct wg_begin_call
{
    struct tcpip_api_call_data call; // deve essere il primo membro
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gateway;
    struct wireguardif_init_data *init;
    struct wireguardif_peer *peer;
    bool set_default;
};

static err_t wg_begin_in_tcpip(struct tcpip_api_call_data *call)
{
    struct wg_begin_call *c = (struct wg_begin_call *)call;

    // Register the new WireGuard network interface with lwIP
    wg_netif = netif_add(&wg_netif_struct, &c->ipaddr, &c->netmask, &c->gateway, c->init, &wireguardif_init, &ip_input);
    if (wg_netif == nullptr)
    {
        return ERR_IF;
    }
    // Mark the interface as administratively up, link up flag is set automatically when peer connects
    netif_set_up(wg_netif);

    // Register the new WireGuard peer with the netwok interface
    wireguardif_add_peer(wg_netif, c->peer, &wireguard_peer_index);
    if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&c->peer->endpoint_ip))
    {
        // Start outbound connection to peer
        wireguardif_connect(wg_netif, wireguard_peer_index);
        if (c->set_default)
        {
            // Save the current default interface for restoring when shutting down the WG interface.
            previous_default_netif = netif_default;
            // Set default interface to WG device.
            netif_set_default(wg_netif);
        }
    }
    return ERR_OK;
}

static err_t wg_end_in_tcpip(struct tcpip_api_call_data *)
{
    // Restore the default interface.
    if (previous_default_netif)
    {
        netif_set_default(previous_default_netif);
        previous_default_netif = nullptr;
    }
    // Disconnect the WG interface.
    wireguardif_disconnect(wg_netif, wireguard_peer_index);
    // Remove peer from the WG interface
    wireguardif_remove_peer(wg_netif, wireguard_peer_index);
    wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
    // Shutdown the wireguard interface.
    wireguardif_shutdown(wg_netif);
    // Remove the WG interface;
    netif_remove(wg_netif);
    wg_netif = nullptr;
    return ERR_OK;
}

bool WireGuard::begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey,
                      const IPAddress &allowedIP, const IPAddress &allowedMask, bool setAsDefault)
{
    struct wireguardif_init_data wg;
    struct wireguardif_peer peer;

    assert(privateKey != NULL);
    assert(remotePeerAddress != NULL);
    assert(remotePeerPublicKey != NULL);
    assert(remotePeerPort != 0);

    if (this->_is_initialized)
        end();

    // Setup the WireGuard device structure
    wg.private_key = privateKey;
    wg.listen_port = remotePeerPort;

    wg.bind_netif = NULL;

    // Initialise the first WireGuard peer structure
    wireguardif_peer_init(&peer);
    // If we know the endpoint's address can add here
    // Un solo tentativo: begin() viene chiamata dal loop di WLED, che non deve bloccarsi
    // per secondi; i nuovi tentativi li gestisce l'usermod.
    bool success_get_endpoint_ip = false;
    for (int retry = 0; retry < 1; retry++)
    {
        ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        struct addrinfo *res = NULL;
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));
        if (lwip_getaddrinfo(remotePeerAddress, NULL, &hint, &res) != 0)
        {
            continue;
        }
        success_get_endpoint_ip = true;
        struct in_addr addr4 = ((struct sockaddr_in *)(res->ai_addr))->sin_addr;
        inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        lwip_freeaddrinfo(res);

        peer.endpoint_ip = endpoint_ip;
        log_i(TAG "%s is %3d.%3d.%3d.%3d", remotePeerAddress, (endpoint_ip.u_addr.ip4.addr >> 0) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 8) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff, (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff);
        break;
    }
    if (!success_get_endpoint_ip)
    {
        log_e(TAG "failed to get endpoint ip.");
        return false;
    }

    peer.public_key = remotePeerPublicKey;
    peer.preshared_key = presharedKey;

    // Rete raggiungibile attraverso il tunnel (AllowedIPs del server lato matrice)
    {
        ip_addr_t allowed_ip = IPADDR4_INIT(static_cast<uint32_t>(allowedIP));
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT(static_cast<uint32_t>(allowedMask));
        peer.allowed_mask = allowed_mask;
    }

    peer.endport_port = remotePeerPort;

    // Initialize the platform
    wireguard_platform_init();

    struct wg_begin_call call;
    memset(&call, 0, sizeof(call));
    call.ipaddr.addr = static_cast<uint32_t>(localIP);
    call.netmask.addr = static_cast<uint32_t>(Subnet);
    call.gateway.addr = static_cast<uint32_t>(Gateway);
    call.init = &wg;
    call.peer = &peer;
    call.set_default = setAsDefault;

    log_i(TAG "connecting wireguard...");
    if (tcpip_api_call(wg_begin_in_tcpip, &call.call) != ERR_OK)
    {
        log_e(TAG "failed to initialize WG netif.");
        wg_netif = nullptr;
        return false;
    }

    this->_is_initialized = true;
    return true;
}

bool WireGuard::begin(const IPAddress &localIP, const IPAddress &Subnet, const IPAddress &Gateway, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey)
{
    // Comportamento originale: tutto il traffico nel tunnel
    return WireGuard::begin(localIP, Subnet, Gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, presharedKey,
                            IPAddress(0, 0, 0, 0), IPAddress(0, 0, 0, 0), true);
}

bool WireGuard::begin(const IPAddress &localIP, const char *privateKey, const char *remotePeerAddress, const char *remotePeerPublicKey, uint16_t remotePeerPort, const char *presharedKey)
{
    // Maintain compatiblity with old begin
    auto subnet = IPAddress(255, 255, 255, 255);
    auto gateway = IPAddress(0, 0, 0, 0);
    return WireGuard::begin(localIP, subnet, gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort, presharedKey);
}

void WireGuard::end()
{
    if (!this->_is_initialized)
        return;

    struct tcpip_api_call_data call;
    memset(&call, 0, sizeof(call));
    tcpip_api_call(wg_end_in_tcpip, &call);

    this->_is_initialized = false;
}

bool WireGuard::is_link_up() const
{
    return this->_is_initialized && wg_netif && netif_is_link_up(wg_netif);
}
