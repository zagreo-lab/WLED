# WireGuard per Retrix

Client WireGuard che collega la matrice al server VPN di Retrix. Deriva dall'usermod `wireguard`
(Aiden Vigue) e include una copia modificata della libreria
[WireGuard-ESP32-Arduino](https://github.com/kienvu58/WireGuard-ESP32-Arduino) (commit `50e2bfd`,
licenza BSD-3, vedi `LICENSE-WireGuard-ESP32`).

## Differenze rispetto all'usermod originale

- **Split tunnel**: nel tunnel passa solo la rete VPN (IP della matrice & maschera, es. `10.8.0.0/24`);
  NTP, aggiornamenti e il resto escono dal Wi-Fi. `full_tunnel` ripristina il comportamento originale.
- Le chiamate lwIP della libreria (interfaccia, peer, timer) girano nel thread tcpip.
- Un solo tentativo DNS per avvio (l'originale bloccava il loop fino a 10 s); nuovo tentativo dopo 30 s.
- Se non c'è handshake per 3 minuti il tunnel viene ricreato (nuova risoluzione DNS dell'host).
- Corretto il parsing dell'IP (`sscanf("%u")` su `uint8_t` scriveva oltre l'array).
- Ora di sistema in UTC via SNTP (server NTP di WLED): non serve più il fuso POSIX.

Non compilarlo insieme all'usermod `wireguard`: usano la stessa libreria e lo stesso ID.

## Compilazione

In `platformio_override.ini`, nell'ambiente usato:

```
custom_usermods =
  usermod_retrix_wg
```

## Configurazione

*Config → Usermods → WireGuard*, oppure `POST /json/cfg` con:

```json
{"um":{"WireGuard":{"enabled":true,"host":"retrix.example.org","port":51820,
 "ip":"10.8.0.2","mask":"255.255.255.0","pem":"<chiave privata matrice>",
 "pub":"<chiave pubblica server>","psk":"<preshared key o vuoto>","full_tunnel":false}}}
```

Lo script `wireguard/peer-to-wled.sh` di node-LEDMatrix genera questo JSON dai file del server.
Limite noto (come nell'usermod originale): le chiavi sono salvate in `cfg.json` e `GET /json/cfg`
le restituisce senza PIN a chiunque raggiunga la matrice. Il PIN di WLED protegge solo la pagina
delle impostazioni e le modifiche.

Lo stato è visibile in *Info*: `in attesa dell'ora (NTP)`, `in attesa dell'handshake`,
`connesso <ip>`.
