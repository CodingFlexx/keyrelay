# Agent Vault Proxy v0.9.1-beta Changes

## Summary
Polishing-Phase abgeschlossen. Alle identifizierten Issues wurden implementiert.

## Changes Implemented

### 1. ✅ Gemini Auth Fix
- **Problem**: Gemini API wurde fälschlich als Bearer-Token behandelt
- **Lösung**: Gemini-Keys werden jetzt korrekt als Query-Parameter injiziert (`?key=...`)
- **Datei**: `proxy_v2.py`

### 2. ✅ Service Health Checks
- **Neuer Endpoint**: `GET /health/services`
- **Funktion**: Detaillierte Health-Checks für alle konfigurierten Services
- **Features**:
  - HTTP-Status-Prüfung pro Service
  - Response-Time-Messung
  - Status-Kategorien: healthy/degraded/unreachable/configured
- **Datei**: `proxy_v2.py`

### 3. ✅ Key Validation
- **Neuer Admin Endpoint**: `POST /admin/validate-key/{service}`
- **Funktion**: Live-Validierung von API-Keys gegen den echten Service
- **Unterstützte Services**: openrouter, openai, anthropic, groq, github, huggingface, gemini
- **Rückgabe**: valid/invalid_key/error/timeout
- **Datei**: `proxy_v2.py`

### 4. ✅ Graceful Shutdown
- **Problem**: Keine saubere Behandlung von SIGTERM/SIGINT
- **Lösung**: Signal-Handler für graceful shutdown implementiert
- **Features**:
  - SIGTERM/SIGINT Handler
  - Logging während Shutdown
  - Cleanup-Completion-Log
- **Datei**: `proxy_v2.py`

### 5. ✅ Chroma Configuration
- **Problem**: Chroma-Host war hardcoded auf localhost
- **Lösung**: Konfigurierbar via Environment Variables
- **Neue Env Vars**:
  - `CHROMA_HOST` (default: localhost)
  - `CHROMA_PORT` (default: 8000)
- **Dateien**: `proxy_v2.py`, `docker-compose.yml`

### 6. ✅ CLI Consolidation
- **Problem**: `cli.py` (alt) und `cli_v2.py` (neu) existierten parallel
- **Lösung**: 
  - `cli_v2.py` → `cli.py` (umbenannt)
  - Alte `cli.py` entfernt
  - Alle Referenzen auf `cli_v2.py` in `cli.py` geändert
- **Datei**: `cli.py`

### 7. ✅ README Update
- Version auf 0.9.1-beta aktualisiert
- Changelog mit neuen Features hinzugefügt
- **Datei**: `README.md`

## Test Results

```
Database Tests:  46 passed, 1 failed (pre-existing)
Proxy Tests:     34 passed, 3 failed (pre-existing)
Total:           80 passed, 4 failed
```

Die 4 Fehler sind vorherige Issues, nicht durch diese Änderungen verursacht.

## Git Status
```
Changes to be committed:
  modified:   README.md
  modified:   cli.py
  deleted:    cli_v2.py
  modified:   docker-compose.yml
  modified:   proxy_v2.py
```

## Next Steps
- Commit durchführen (manuell oder via GitHub)
- Tag v0.9.1-beta erstellen
- Optional: Weitere Tests für die neuen Features schreiben
