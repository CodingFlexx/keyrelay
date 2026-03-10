# Deployment-Szenarien

KeyRelay bietet drei offizielle Deployment-Szenarien. Diese drei Varianten sind die Grundlage fuer Doku, Onboarding und Sicherheitsempfehlungen.

Empfohlener Einstieg fuer alle drei Varianten (Docker + Bootstrap + UI):

Danach die passende Compose-Datei aus `examples/` verwenden, Bootstrap-Credentials setzen und starten.

*(Hinweis: Der Master-Key `agent_vault_key` wird beim ersten Start automatisch vom Container generiert, es ist kein manuelles Python-Skript mehr noetig.)*

## Szenario 1: Agent nativ auf dem Host, KeyRelay im Docker-Container

```text
Agent (Host) -> localhost / Docker Port Mapping -> KeyRelay Container -> Provider APIs
```

Empfohlen fuer:
- lokale Entwicklung und Einzelplatz-Nutzung
- gutes Anti-Leak- und Prompt-Injection-Verhalten ohne zweiten Host

Empfohlene Einstellungen:
- `KEYRELAY_SECURITY_MODE=hardened_local`
- `REQUIRE_AGENT_AUTH=true`
- Vault-Key als Secret-Datei / Docker-Secret
- Proxy-User mit engen Scopes

Compose-Vorlage:

```bash
docker compose -f examples/docker-compose.local.yml up -d
```

Wichtige Grenzen:
- Ein Agent mit Root auf dem Host bleibt ein starker Angreifer
- Docker ist hier keine harte Vertrauensgrenze gegen Host-Root

## Szenario 2: Agent und KeyRelay in separaten Containern auf demselben Host

```text
Agent Container -> internes Docker Netzwerk -> KeyRelay Container -> Provider APIs
```

Empfohlen fuer:
- lokale Multi-Agent-Umgebungen
- bessere Isolation als im nativen Host-Modell

Empfohlene Einstellungen:
- `KEYRELAY_SECURITY_MODE=hardened_local`
- separates Docker-Netz fuer interne Kommunikation
- kein Docker-Socket fuer den Agent-Container
- keine geteilten Secret- oder Daten-Volumes
- Proxy-User pro Agent mit klaren `--scope` Werten

Compose-Vorlage:

```bash
docker compose -f examples/docker-compose.multi.yml up -d
```

Wichtige Grenzen:
- Wer den Host oder Docker selbst kontrolliert, kann beide Container angreifen
- Same-Host bleibt ein „erschwert“, aber kein „hart isoliert“

## Szenario 3: Agent lokal oder im Container, KeyRelay auf zweitem Host im Netzwerk

```text
Agent -> HTTPS Reverse Proxy -> KeyRelay auf Host B -> Provider APIs
```

Empfohlen fuer:
- sicherheitsfokussierte Deployments
- boesartige oder kompromittierte Agenten als realistisches Bedrohungsmodell

Empfohlene Einstellungen:
- `KEYRELAY_SECURITY_MODE=remote_secure`
- `REQUIRE_AGENT_AUTH=true`
- TLS/HTTPS ueber Reverse Proxy
- Secret-Datei auf dem Relay-Host
- Proxy-User nur mit benoetigten Scopes

Compose-Vorlage:

```bash
docker compose -f examples/docker-compose.remote.yml up -d
```

Vorteile:
- Provider-Secrets liegen nicht auf dem Agent-Host
- deutlich bessere Trennung zwischen Agent und Secret-Verwaltung

## Bootstrap und Onboarding

Beim ersten Start kann der Container automatisch initialisieren:

- DB-Init, falls noch keine `vault.db` vorhanden ist
- Bootstrap-User, wenn `BOOTSTRAP_ADMIN_USERNAME` und `BOOTSTRAP_ADMIN_PASSWORD` gesetzt sind
- optional API-Key-Datei via `BOOTSTRAP_ADMIN_API_KEY_PATH`

Empfohlener Ablauf:

1. Compose-Datei aus `examples/` kopieren/anpassen
2. Bootstrap-Variablen setzen (mindestens User + Passwort)
3. Container starten
4. `GET /admin/ui` im Browser oeffnen und Services/Users konfigurieren

CLI-Onboarding bleibt als Alternative erhalten:

`python3 cli.py setup` fragt explizit nach dem Deployment-Szenario und leitet daraus passende Defaults und Hinweise ab:

- Szenario 1 -> `hardened_local`
- Szenario 2 -> `hardened_local`
- Szenario 3 -> `remote_secure`

Zusatz:
- optionaler Bulk-Import aus `.env` / JSON
- Scope-Auswahl fuer Agent-User
- optionaler Live-Key-Test beim Hinzufuegen

## Welche Variante sollte man waehlen?

- Wenn das Hauptziel „kein unabsichtliches Leaken“ ist und alles lokal laufen soll: Szenario 1 oder 2
- Wenn aktive Exfiltration durch kompromittierte Agents realistisch ist: Szenario 3
- Wenn mehrere Agents auf einem Host laufen: Szenario 2 statt Szenario 1
