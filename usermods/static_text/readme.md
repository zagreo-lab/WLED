# Usermod "Static Text" per WLED 16.x - usa il fontManager interno di WLED
Versione: v.2
Zagreo@30.09.2026

## Comandi:
 (stessi font, UTF-8/accenti e font personalizzati .wbf dello Scrolling Text).
 
   Speed   -> "Align L/C/R"  0-84 sinistra | 85-169 centro | 170-255 destra
   Inten.  -> "Y Offset"     128 = centrato in verticale
   Custom1 -> "X Offset"     128 = nessuno spostamento
   Custom2 -> "Spacing"      spaziatura extra 0..3 px (si somma a quella del font)
   Custom3 -> "Font (0-4)"   indice esatto del font (0..31; i font integrati vanno da 0 a 4)
   Check1  -> "Custom Font"  usa i font personalizzati caricati sulla scheda
   Colore 1 = testo, Colore 2 = sfondo
 
 Nome segmento vuoto -> mostra l'ora HH:MM.
 