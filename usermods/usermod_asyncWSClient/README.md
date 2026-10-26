# Retrix Cloud Client (usermod WLED)

Client WebSocket in uscita (`ws://`, senza TLS) verso Retrix. La matrice apre la connessione:
non servono port forwarding né l'API di WLED esposta.

## Installazione
Copia `usermod_asyncWSClient.cpp` e `retrix_ws_codec.h` **nella stessa cartella** del tuo usermod.
Poi in *Config → Usermods → Retrix Cloud Client*: `enabled`, `host`, `port`, `path` (default `/wled-ws`).
È **disabilitato di default** e l'host è vuoto.

Opzioni di compilazione (`-D`): `RETRIX_WS_STATUS_INTERVAL` (ms, default 5000), `RETRIX_WS_MAX_MSG`
(byte, default 8192), `RETRIX_WS_ONLY_ONOFF` (ripiego: solo "ON"/"OFF" come nella versione originale,
senza le chiamate interne di WLED per applicare uno stato JSON).

## Protocollo (provvisorio, senza autenticazione)
- matrice → server: `{"t":"hello","id":"<MAC>","name":"…","ver":"…"}` all'apertura
- matrice → server: `{"t":"state","on":true,"bri":128}` ogni `RETRIX_WS_STATUS_INTERVAL` ms
- server → matrice: stato WLED in JSON (come `POST /json/state`), oppure `ON` / `OFF`

## Prova senza Retrix
```
npm i ws && node ws-test-server.mjs 3099
```
Comandi da tastiera: `ON`, `OFF`, `big` (stato da ~2 KB), `ping`, `close`, oppure un JSON (`{"on":false,"bri":20}`).

## Test eseguiti su PC
`tests/` contiene il test del codec contro un server `ws` reale e un simulatore che fa girare l'usermod
con stub di WLED/AsyncTCP (non sono il vero WLED). Servono `g++`, `node`, il pacchetto `ws` e
`ArduinoJson-v6.21.5.h` salvato come `tests/stubs/ArduinoJson.h`.
```
cd tests
g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined test_ws_codec.cpp -o test_ws_codec
g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined -Istubs -DRETRIX_WS_STATUS_INTERVAL=300UL sim_usermod.cpp -o sim_usermod
node ../ws-test-server.mjs 3198 --selftest &  ./test_ws_codec 3198
```
