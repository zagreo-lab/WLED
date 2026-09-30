#include "wled.h"
#include "fontmanager.h"   // definizione completa di FontManager (FX.h ne ha solo la forward declaration)

/*
 * Zagreo@30.09.2026 v.2
 *
 * Usermod "Static Text" v2 per WLED 16.x - usa il fontManager interno di WLED
 * (stessi font, UTF-8/accenti e font personalizzati .wbf dello Scrolling Text).
 *
 *   Speed   -> "Align L/C/R"  0-84 sinistra | 85-169 centro | 170-255 destra
 *   Inten.  -> "Y Offset"     128 = centrato in verticale
 *   Custom1 -> "X Offset"     128 = nessuno spostamento
 *   Custom2 -> "Spacing"      spaziatura extra 0..3 px (si somma a quella del font)
 *   Custom3 -> "Font (0-4)"   indice esatto del font (0..31; i font integrati vanno da 0 a 4)
 *   Check1  -> "Custom Font"  usa i font personalizzati caricati sulla scheda
 *   Colore 1 = testo, Colore 2 = sfondo
 * 
 * Nome segmento vuoto -> mostra l'ora HH:MM.
 */

static void mode_staticText() {
  if (!strip.isMatrix || !SEGMENT.is2D()) {   // non e' un setup 2D: riempi col colore 1 ed esci
    SEGMENT.fill(SEGCOLOR(0));
    return;
  }
  FontManager fontManager(&SEGMENT);   // istanza locale, come in mode_2Dscrollingtext
  const int cols = SEG_W;
  const int rows = SEG_H;

  // testo dal nome del segmento, oppure l'ora se vuoto
  char text[WLED_MAX_SEGNAME_LEN + 1] = {'\0'};
  if (SEGMENT.name && SEGMENT.name[0] != '\0') {
    strlcpy(text, SEGMENT.name, sizeof(text));
  } else {
    snprintf(text, sizeof(text), "%02d:%02d", hour(localTime), minute(localTime));
    fontManager.cacheNumbers(true);  // evita di ricaricare i numeri a ogni minuto
  }

  const bool useCustomFont = SEGMENT.check1;
  // indice esatto del font: valore dello slider (0..31), max 4 per i font integrati
  uint8_t fontNum = SEGMENT.custom3;
  if (!useCustomFont && fontNum > 4) fontNum = 4;

  if (!fontManager.loadFont(fontNum, text, useCustomFont)) return;

  const int fontHeight = fontManager.getFontHeight();
  const int spacing    = fontManager.getFontSpacing() + (SEGMENT.custom2 >> 6);   // 0..3 px

  // larghezza totale del testo
  const int numberOfChars = utf8_strlen(text);
  int totalWidth = 0;
  int idx = 0;
  for (int c = 0; c < numberOfChars; c++) {
    uint8_t charLen;
    uint32_t unicode = utf8_decode(&text[idx], &charLen);
    idx += charLen;
    totalWidth += fontManager.getGlyphWidth(unicode) + spacing;
  }
  totalWidth -= spacing;

  // allineamento + offset
  int x0;
  if (SEGMENT.speed < 85)       x0 = 0;                       // sinistra
  else if (SEGMENT.speed < 170) x0 = (cols - totalWidth) / 2; // centro
  else                          x0 = cols - totalWidth;       // destra
  x0 += ((int)SEGMENT.custom1 - 128) * cols / 256;
  const int y0 = (rows - fontHeight) / 2 + ((int)SEGMENT.intensity - 128) * rows / 256;

  const uint32_t fg = SEGCOLOR(0);
  SEGMENT.fill(SEGCOLOR(1));

  // disegno (col2 = col1 -> colore singolo, come Scrolling Text senza gradiente)
  idx = 0;
  int cx = x0;
  for (int c = 0; c < numberOfChars; c++) {
    uint8_t charLen;
    uint32_t unicode = utf8_decode(&text[idx], &charLen);
    idx += charLen;
    const int gw = fontManager.getGlyphWidth(unicode);
    if (cx >= cols) break;                       // oltre il bordo destro
    if (cx + gw + spacing >= 0) {
      fontManager.drawCharacter(unicode, cx, y0, fg, fg, 0);
    }
    cx += gw + spacing;
  }
}
static const char _data_FX_MODE_STATIC_TEXT[] PROGMEM =
  "Static Text@Align L/C/R,Y Offset,X Offset,Spacing,Font (0-4),Custom Font;!,!;;2;sx=128,ix=128,c1=128,c2=0,c3=0";

class StaticTextUsermod : public Usermod {
  public:
    void setup() override {
      strip.addEffect(255, &mode_staticText, _data_FX_MODE_STATIC_TEXT);
    }
    void loop() override {}
};

static StaticTextUsermod static_text_usermod;
REGISTER_USERMOD(static_text_usermod);