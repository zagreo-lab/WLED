// retrix_ws_codec.h
// v.1.0 
// 25.10.2026
//
// Codec WebSocket lato client (RFC 6455, senza estensioni, senza TLS) per l'usermod
// "Retrix Cloud Client". Nessuna dipendenza da WLED/Arduino/AsyncTCP: si compila anche
// su PC ed è testato contro il server "ws" di Node (vedi tests/).
//
// Il parser è una macchina a stati che lavora byte per byte: non fa nessuna ipotesi su
// come TCP spezza o unisce i dati (un frame può arrivare in più pezzi, più frame o la
// risposta 101 insieme al primo frame nello stesso pacchetto).

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>

#ifndef RETRIX_WS_MAX_MSG
#define RETRIX_WS_MAX_MSG 8192   // dimensione massima di un messaggio ricevuto (byte)
#endif

namespace retrix {

// Eventi prodotti dal parser. I callback vengono chiamati durante feed().
class WsSink {
public:
  virtual ~WsSink() {}
  virtual void onOpen() = 0;                                  // risposta 101 ricevuta: il canale è aperto
  virtual void onText(const char* msg, size_t len) = 0;       // messaggio di testo completo (terminato da '\0')
  virtual void onPing(const uint8_t* payload, size_t len) = 0;// il server ha mandato un ping: rispondere con pong
  virtual void onClose(uint16_t code) = 0;                    // il server ha chiuso (1005 = senza codice)
  // Errore: il flusso non è più utilizzabile. closeCode != 0: frame di chiusura da inviare (1002, 1009).
  virtual void onError(const char* reason, uint16_t closeCode) = 0;
};

inline std::string base64Encode(const uint8_t* data, size_t len) {
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = (uint32_t)data[i] << 16;
    if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
    if (i + 2 < len) v |= data[i + 2];
    out += tbl[(v >> 18) & 63];
    out += tbl[(v >> 12) & 63];
    out += (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
    out += (i + 2 < len) ? tbl[v & 63] : '=';
  }
  return out;
}

// Escape minimo per inserire una stringa in un JSON scritto a mano.
inline std::string jsonEscape(const char* s) {
  std::string out;
  for (; s && *s; ++s) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { out += '\\'; out += (char)c; }
    else if (c < 0x20)         { out += ' '; }
    else                       { out += (char)c; }
  }
  return out;
}

inline std::string buildHandshakeRequest(const char* host, uint16_t port, const char* path,
                                         const std::string& keyBase64) {
  std::string p = (path && path[0]) ? path : "/";
  if (p[0] != '/') p = "/" + p;

  std::string req = "GET " + p + " HTTP/1.1\r\nHost: " + host;
  if (port != 80) req += ":" + std::to_string(port);
  req += "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + keyBase64 +
         "\r\nSec-WebSocket-Version: 13\r\n\r\n";
  return req;
}

// Costruisce un frame del client (sempre mascherato, FIN=1). Ritorna la lunghezza scritta
// in out, oppure 0 se il payload supera 65535 byte o non entra in outCap.
inline size_t buildClientFrame(uint8_t opcode, const uint8_t* payload, size_t len, uint32_t maskKey,
                               uint8_t* out, size_t outCap) {
  const size_t hdr = 2 + (len >= 126 ? 2 : 0) + 4;
  if (len > 65535 || hdr + len > outCap) return 0;

  size_t i = 0;
  out[i++] = (uint8_t)(0x80 | (opcode & 0x0F));
  if (len < 126) {
    out[i++] = (uint8_t)(0x80 | len);
  } else {
    out[i++] = (uint8_t)(0x80 | 126);
    out[i++] = (uint8_t)(len >> 8);
    out[i++] = (uint8_t)(len & 0xFF);
  }

  const uint8_t mask[4] = { (uint8_t)(maskKey >> 24), (uint8_t)(maskKey >> 16),
                            (uint8_t)(maskKey >> 8),  (uint8_t)maskKey };
  memcpy(out + i, mask, 4);
  i += 4;

  for (size_t k = 0; k < len; k++) out[i + k] = payload[k] ^ mask[k & 3];
  return i + len;
}

class WsCodec {
public:
  WsCodec() { reset(); }

  // Da chiamare a ogni nuova connessione TCP, prima dell'handshake.
  void reset() {
    _phase = P_HANDSHAKE;
    _hs.clear();
    _msg.clear();
    _msgActive = false;
    _msgType = 0;
    _pos = 0;
    _len = 0;
  }

  bool isOpen() const { return _phase != P_HANDSHAKE && _phase != P_DEAD; }

  void feed(const uint8_t* data, size_t len, WsSink& sink) {
    size_t i = 0;
    while (i < len && _phase != P_DEAD) {
      switch (_phase) {

        case P_HANDSHAKE: {
          _hs += (char)data[i++];
          if (_hs.size() > 2048) { fail(sink, "handshake response too long", 0); break; }

          const size_t n = _hs.size();
          if (n >= 4 && _hs.compare(n - 4, 4, "\r\n\r\n") == 0) {
            // Stato 101 con HTTP/1.0 o 1.1: alcuni server (es. WebSocket Debug Tools) rispondono 1.0.
            const bool upgraded = n >= 16 && _hs.compare(0, 7, "HTTP/1.") == 0 &&
                                  (_hs[7] == '0' || _hs[7] == '1') &&
                                  _hs.compare(8, 4, " 101") == 0 && (_hs[12] == ' ' || _hs[12] == '\r');
            if (!upgraded) {
              const std::string line = _hs.substr(0, _hs.find("\r\n"));
              fail(sink, ("handshake rejected: " + line).c_str(), 0);
              break;
            }
            _hs.clear();
            _phase = P_HDR0;
            sink.onOpen();
          }
          break;
        }

        case P_HDR0: {
          const uint8_t b = data[i++];
          _fin = (b & 0x80) != 0;
          _opcode = b & 0x0F;
          if (b & 0x70) { fail(sink, "RSV bits set", 1002); break; }
          if (!(_opcode <= 2 || (_opcode >= 8 && _opcode <= 10))) { fail(sink, "unknown opcode", 1002); break; }
          _phase = P_HDR1;
          break;
        }

        case P_HDR1: {
          const uint8_t b = data[i++];
          _masked = (b & 0x80) != 0;
          const uint8_t l7 = b & 0x7F;
          _isControl = _opcode >= 8;
          if (_isControl && (!_fin || l7 > 125)) { fail(sink, "invalid control frame", 1002); break; }

          _len = l7;
          _extNeeded = (l7 == 126) ? 2 : (l7 == 127) ? 8 : 0;
          _extRead = 0;
          if (_extNeeded) { _len = 0; _phase = P_EXTLEN; }
          else            { afterLength(sink); }
          break;
        }

        case P_EXTLEN: {
          _len = (_len << 8) | data[i++];
          if (++_extRead == _extNeeded) {
            if (_extNeeded == 8 && (_len >> 63)) { fail(sink, "invalid length", 1002); break; }
            afterLength(sink);
          }
          break;
        }

        case P_MASK: {
          _mask[_maskPos++] = data[i++];
          if (_maskPos == 4) beginPayload(sink);
          break;
        }

        case P_PAYLOAD: {
          const uint64_t remaining = _len - _pos;
          const uint64_t available = (uint64_t)(len - i);
          const size_t n = (size_t)(remaining < available ? remaining : available);
          consume(data + i, n);
          i += n;
          _pos += n;
          if (_pos == _len) endFrame(sink);
          break;
        }

        default:
          return;
      }
    }
  }

private:
  enum Phase : uint8_t { P_HANDSHAKE, P_HDR0, P_HDR1, P_EXTLEN, P_MASK, P_PAYLOAD, P_DEAD };

  Phase _phase = P_HANDSHAKE;
  std::string _hs;                 // risposta HTTP in arrivo

  bool _fin = false;
  bool _masked = false;
  bool _isControl = false;
  uint8_t _opcode = 0;
  uint8_t _extNeeded = 0;
  uint8_t _extRead = 0;
  uint8_t _maskPos = 0;
  uint8_t _mask[4] = {0, 0, 0, 0};
  uint64_t _len = 0;
  uint64_t _pos = 0;

  uint8_t _ctl[125];               // payload dell'ultimo frame di controllo
  std::string _msg;                // messaggio di testo in assemblaggio
  bool _msgActive = false;         // messaggio frammentato non ancora concluso
  uint8_t _msgType = 0;            // 1 = testo, 2 = binario (scartato)

  void fail(WsSink& sink, const char* reason, uint16_t closeCode) {
    _phase = P_DEAD;
    sink.onError(reason, closeCode);
  }

  void afterLength(WsSink& sink) {
    _maskPos = 0;
    if (_masked) _phase = P_MASK;     // i server non devono mascherare, ma lo gestiamo
    else         beginPayload(sink);
  }

  void beginPayload(WsSink& sink) {
    _pos = 0;

    if (!_isControl) {
      if (_opcode == 0) {
        if (!_msgActive) { fail(sink, "unexpected continuation frame", 1002); return; }
      } else {
        if (_msgActive) { fail(sink, "new data frame inside a fragmented message", 1002); return; }
        _msgActive = true;
        _msgType = _opcode;
        _msg.clear();
      }

      if (_msgType == 1) {
        if ((uint64_t)_msg.size() + _len > (uint64_t)RETRIX_WS_MAX_MSG) {
          fail(sink, "message too big", 1009);
          return;
        }
        _msg.reserve(_msg.size() + (size_t)_len);
      }
    }

    _phase = P_PAYLOAD;
    if (_len == 0) endFrame(sink);
  }

  void consume(const uint8_t* p, size_t n) {
    if (_isControl) {
      for (size_t k = 0; k < n; k++) {
        const size_t idx = (size_t)_pos + k;
        _ctl[idx] = _masked ? (uint8_t)(p[k] ^ _mask[idx & 3]) : p[k];
      }
    } else if (_msgType == 1) {
      const size_t base = _msg.size();
      _msg.append((const char*)p, n);
      if (_masked) {
        for (size_t k = 0; k < n; k++)
          _msg[base + k] = (char)((uint8_t)_msg[base + k] ^ _mask[((size_t)_pos + k) & 3]);
      }
    }
    // messaggi binari: scartati
  }

  void endFrame(WsSink& sink) {
    _phase = P_HDR0;

    if (_isControl) {
      const size_t n = (size_t)_len;
      if (_opcode == 9) {
        sink.onPing(_ctl, n);
      } else if (_opcode == 8) {
        const uint16_t code = n >= 2 ? (uint16_t)((_ctl[0] << 8) | _ctl[1]) : (uint16_t)1005;
        _phase = P_DEAD;
        sink.onClose(code);
      }
      return;                               // 10 (pong): ignorato
    }

    if (_fin) {
      _msgActive = false;
      if (_msgType == 1) {
        std::string m;
        m.swap(_msg);
        sink.onText(m.c_str(), m.size());
      } else {
        _msg.clear();
      }
    }
  }
};

}  // namespace retrix