# Review: Sperrensynchronisation zwischen drei NS8-Hosts

Stand: 29.10.2026. Review von `6a2eba090e476651fe868bb3d033d0e1689f4977`.
Aufgabe: `20261029-codex-sync-review` in agent-exchange. Dieses Dokument ist
eine Empfehlung, keine beschlossene Architekturänderung und keine Rolloutfreigabe.

## Ergebnis

Für die beschriebene Umgebung ist der bestehende integrierte Koordinator auf
dem dauerhaft betriebenen ersten Netcup-NS8 die passende Lösung. Alle drei
NS8-Hosts betreiben lokale Erkennung und Firewall; beide anderen Hosts verbinden
sich als Peers mit demselben HTTPS-Endpunkt. Clusterzugehörigkeit beeinflusst
diesen Austausch nicht. Der spätere Clusterbeitritt braucht keinen zweiten
Synchronisationsweg. Der Test-/IdP-Host ist als Koordinator weniger geeignet,
weil er voraussichtlich häufiger verändert wird.

Der Debian-Server wird dafür nicht benötigt. Eine separate Datenbank allein
liefert keine Ereignisvalidierung, Konfliktauflösung oder Firewallverteilung.
SQLite-Dateien und Fail2ban-Laufzeitdatenbanken dürfen nicht zwischen den Hosts
kopiert oder gemeinsam über NFS/SMB geöffnet werden.

## Topologie und Transport

```text
NS8 A bei Netcup: Erkennung + Firewall + HTTPS-Koordinator + lokale SQLite
       ^                         ^
       | HTTPS                   | HTTPS über geroutetes Standort-VPN
       v                         v
NS8 B bei Netcup             NS8 C hinter Fritzbox
Erkennung + Firewall         Erkennung + Firewall
später Cluster-Node2          eigenständiger NS8
```

Jeder Peer lädt eigene Ban-Ereignisse hoch und holt gemeinsame Änderungen ab.
Der Heimhost braucht ausgehend HTTPS und einen funktionierenden Rückweg;
für die Synchronisation ist keine eingehende Freigabe an der Fritzbox nötig.

Für den Sollbetrieb: stabiler DNS-Name wie `bans.example.org`, intern auf die
private Adresse von NS8 A auflösen. B erreicht A über eth1, C über das geroutete
VPN. Nach dem Clusterbeitritt kann der Transport zwischen A/B alternativ über
das NS8-WireGuard-Netz erfolgen. Das ist eine Transportänderung, keine eigene
Sperrenverteilung. Ein einheitlicher Weg über das bestehende private Netz bleibt
einfacher, solange Routing und Schutz passen. Privates VLAN und VPN-Verschlüsselung
nicht gleichsetzen: HTTPS samt Zertifikatsprüfung bleibt erforderlich.

**Bestehende Implementierung:** Der API-Dienst bindet an Loopback; NS8 Traefik
veröffentlicht den Hostnamen. Die Modulroute enthält derzeit keine IP-ACL und
fordert automatisch Let's Encrypt an. Private DNS-Auflösung allein macht einen
über eth0 erreichbaren Traefik-Router nicht privat. Für ausschließlich private
API-Nutzung sind eine passende Router-ACL oder vergleichbare Zugangsbeschränkung
und ein getesteter Zertifikatsweg nötig. HTTP-01-Erreichbarkeit für ACME beachten;
private-only mit interner CA oder DNS-01 ist nicht bereits als Moduloption gebaut.
Keine pauschale Sperre von Port 443, da dort auch andere NS8-Anwendungen liegen.
Mit vorhandener öffentlicher HTTPS-Route funktioniert das Modul grundsätzlich
bereits; private-only ist eine gesondert zu prüfende Härtung.

## Bewertung des vorhandenen Protokolls

- Zentraler maßgeblicher Zustand in lokaler SQLite, Übertragung über API.
- Dauerhafte lokale Queue; neue lokale Sperren gelten auch bei fehlendem Sync.
- Drei Sekunden Pollintervall, lokale Firewall-Schleife mit 0,5 Sekunden Pause.
  Unter geringer Last ist Verteilung in wenigen Sekunden plausibel, kein
  garantiertes Zeitlimit. Es werden Sperrentscheidungen geteilt, keine
  hostübergreifenden Fehlversuchszähler.
- Ereignis-IDs und Transaktionen behandeln Wiederholungen und gleichzeitige Bans.
- Revisionsmarker verhindern, dass verspätete Ereignisse eine inzwischen
  aufgehobene Sperre innerhalb des unterstützten Offlinefensters wiederherstellen.
- Gemeinsame Whitelist mit Konflikterkennung bei gleichzeitiger Bearbeitung.
- Deltaübertragung, paginierte Vollübernahme, Identitäts-/Rollback-Prüfung.
- Bis sieben Tage Offlinezeit: lokale Ereignisse nachliefern. Bei Rückkehr nach
  mehr als sieben Tagen: aktuelle Koordinatorliste übernehmen und noch nicht
  synchronisierte lokale Sperren verwerfen. Solange der Host offline bleibt,
  gibt es dadurch keinen automatischen lokalen Ban-Ablauf.
- Koordinatorausfall unterbricht Austausch und globale manuelle Änderungen;
  jeder Host behält vorhandene Sperren und erkennt neue lokal. Kein automatisches
  Failover. Cluster-Leaderwechsel repliziert diese Anwendungsdatenbank nicht.

Diese Eigenschaften passen zu drei Hosts ohne Forderung nach hochverfügbarer
Zentrale. Zeitabgleich/NTP ist wegen Ereignisalter und Retention relevant.
Koordinator regelmäßig per konsistentem NS8-Modulbackup sichern. Mehrere aktive
Koordinatoren oder eine bloße Kopie seiner Datenbank erzeugen keine sichere HA.

## Sicherheitsbefunde und fachliche Grenzen

1. **Gitea-Log-Injektion besteht fort.** `parsers.gitea()` liefert auf dem
   geprüften Commit für eine synthetische Logzeile mit eingeschleustem
   `from 192.0.2.77:1:` im Benutzernamen die Opferadresse `192.0.2.77` statt der
   echten Quelladresse `198.51.100.23`. Der Angriff wurde historisch mit echtem
   Gitea 28.0.0 dokumentiert; hier wurde nur die Parserwirkung erneut geprüft.
   Das ist besonders relevant bei permanenten globalen Bans. Vor produktiver
   Nutzung dieser Erkennung eine verlässliche strukturierte Quelle oder passende
   Proxy-Logs mit nachgewiesener Login-Semantik implementieren und prüfen.
   HTTP 200 allein ist kein universeller Beleg eines fehlgeschlagenen Logins.
2. **Gemeinsamer Token mit umfassenden Rechten.** Derselbe Bearer-Token erlaubt
   Sync, Unban und Whitelist-Änderungen. Ein Peer kann auch Identität und geschützte
   Netze im Payload angeben. Das Konzept setzt vollständig vertrauenswürdige
   Peers voraus. Sinnvolle Weiterentwicklung: widerrufbare Zugangsdaten pro Peer,
   Bindung an dessen Identität und getrennte Verwaltungsrechte. Dies ist aktuell
   nicht implementiert und für einen fremdverwalteten Teilnehmer unzureichend.
3. **Whitelist umfasst Paketadressen.** Öffentliche Host-/VPN-Endpunktadressen,
   private Hostadressen, Gateway-/Managementadressen und tatsächliches Cluster-VPN
   schützen, bevor globale Sperren aktiviert werden. `10.5.0.0/24` und bei bewusst
   vertrautem Heimnetz `192.168.178.0/24` können geschützt werden. Eine ganze
   Heimnetzfreigabe nimmt auch kompromittierte LAN-Clients von IP-Bans aus;
   alternativ gezielt Hosts/Gateways/Administrationsadressen erlauben. Die frühere
   Nutzerentscheidung zugunsten manueller VPN-Whitelist bleibt gültig.
4. **eth1 ist nicht automatisch vertraut.** Laut NS8-Dokumentation ist wg0
   trusted; andere Interfaces gehören standardmäßig zur public-Zone. Routing,
   tatsächliche Zonen und TCP-443-Erreichbarkeit separat prüfen. Das tatsächliche
   NS8-Overlay darf nicht mit `10.5.0.0/24` oder `192.168.178.0/24` kollidieren;
   seine Adresse ist hier unbekannt.
5. **Vaultwarden/IdP nicht abgedeckt.** Eingebaute Quellen: SSH, NS8-Admin,
   Gitea, Organizr und Samba. Eine Synchronisation liefert keine zusätzlichen
   Detektoren. Welche IdP-Software läuft, ist nicht bekannt. Erkennungsregeln mit
   echten fehlgeschlagenen Logins, 2FA und Client-IP-Zuordnung separat prüfen.
6. **NAT/Proxys:** Bei normalem DNAT an der Fritzbox kann die öffentliche
   Clientadresse erhalten bleiben; SNAT oder vorgelagerte Proxys können sie
   verdecken. Anwendungslog und am NS8 sichtbare Paketquelle vergleichen. Eine
   Host-Firewall kann eine nur im HTTP-Header sichtbare Adresse nicht sperren.

## Alternativen

| Variante | Bewertung für diese Umgebung |
| --- | --- |
| Integrierter NS8-Koordinator, zwei Peers | Empfehlung; bestehende Implementierung, ein Protokoll, lokale Offlinefunktion |
| Cluster-intern Redis/Eventbus plus separater externer Sync | Zusätzliche Entwicklung und zwei Konsistenzwege ohne belegten Vorteil |
| Debian nur als externe PostgreSQL-/MariaDB-Instanz | Nicht unterstützt und löst die Synchronisation allein nicht |
| Vollständiger Koordinator auf Debian mit lokaler SQLite | Technisch möglich als neue Paketierung; NS8-unabhängige Wartung, aber Aufwand für Lifecycle/TLS/Auth/Backup und weiterhin ein Ausfallpunkt |
| CrowdSec-LAPI auf Debian, Agenten und Bouncer auf allen Hosts | Etablierte Alternative bei geplantem Ausbau auf Nicht-NS8-Hosts; Migration samt Parsern, Ablaufregeln und Offlineverhalten nötig |

CrowdSec unterstützt offiziell gemischte Betriebssysteme und getrennte
Logprozessoren/LAPI/Bouncer. Das vorhandene Projekt `ns8-crowdsec-companion` ist
deshalb bei einer solchen Migration mitzuberücksichtigen. Sein historischer
Bericht ist kein aktueller Betriebsnachweis; hier wurde dessen Code nicht neu
geprüft. Kein Wechsel allein wegen dieser drei NS8-Hosts empfohlen.

## Abnahme vor Rollout

Auf drei Wegwerfinstanzen: Sperre von jedem Host auf beide anderen übertragen,
global entsperren, Whitelist-Konflikt prüfen, VPN trennen, lokale Sperre erzeugen,
neu starten, wieder verbinden und Ban/Unban-Replay prüfen. Rückkehr nach mehr
als sieben Tagen durch kontrollierte Zeit-/Zustandssimulation testen. IPv4/IPv6,
Input/Output/Forward, alle Interfaces, firewalld-Neuladung und konsistente
Backup/Wiederherstellung einbeziehen. Für echte Anwendungen Client-IP und
Fehlversuchserkennung gesondert bestätigen. Zertifikatsausstellung/-erneuerung,
Split-DNS und Zugangsbegrenzung von außen prüfen.

Der spätere Beitritt von B ist eine getrennte Migration: NS8 kann zwei bereits
bestehende Cluster nicht einfach zusammenführen. Anwendungsbackup/-restore und
Neuaufnahme planen; keine parallelen restaurierten Kopien derselben App-UUID.
Das Sperrensync-Konzept setzt den Clusterbeitritt nicht voraus.

## Tatsächliche Prüfung

- Aktuellen Remote-main isoliert gelesen; keine Laufzeitdateien verändert.
- `PYTHONPATH=imageroot/pypkg python3 -m unittest discover -s tests -v`:
  71 Tests, 70 erfolgreich, ein echter Engine-Test mangels `FAIL2BAN_SOURCE`
  übersprungen. Enthalten: Sync, Offline, Replay, Whitelist, HTTP, Parser,
  Firewall-Regelgenerierung. Kein neuer Kernel-/NS8-Live-Test.
- Synthetische Gitea-Injektionsfixture gegen aktuellen Parser reproduziert.
- Main-CI `40256280959` erfolgreich, inklusive vorhandener VM-Prüfungen;
  kein Nachweis für drei reale Hosts oder echten Standort-VPN-Ausfall.
- Keine Nutzerhosts kontaktiert, keine Netz-/Firewallfreigabe verändert,
  kein Merge, Release oder Deployment durchgeführt.

## Primärquellen

- [Geprüfter Modulstand](https://github.com/Platypuschan/ns8-fail2ban-reworked/tree/6a2eba090e476651fe868bb3d033d0e1689f4977), insbesondere `registry.py`, `node.py`, `worker.py`, `transport.py`, `lifecycle.py`, `parsers.py` und `tests/test_core.py` unter den jeweiligen Quell-/Testverzeichnissen.
- [Main-CI](https://github.com/Platypuschan/ns8-fail2ban-reworked/actions/runs/40256280959).
- [NS8-Clusterverwaltung](https://docs.nethserver.org/projects/ns8/en/latest/cluster.html).
- [NS8-Firewall](https://docs.nethserver.org/projects/ns8/en/latest/firewall.html).
- [NS8-VPN](https://docs.nethserver.org/docs/tutorial/vpn).
- [NS8-Installation und nicht nachträglich änderbarer VPN-Bereich](https://docs.nethserver.org/projects/ns8/en/latest/install.html).
- [SQLite über Netzwerkdateisysteme](https://sqlite.org/useovernet.html).
- [CrowdSec-Multiserver-Architektur](https://docs.crowdsec.net/u/user_guides/multiserver_setup/).
- [CrowdSec-Authentifizierung](https://docs.crowdsec.net/u/user_guides/machines_mgmt/).
- [Historischer Gitea-Befund](https://github.com/Platypuschan/agent-exchange/blob/main/handoffs/ns8-fail2ban-reworked/2026-10-13-gitea-log-injection.md).
