# AHX WP SSO

AHX WP SSO betreibt einen eigenständigen WordPress-SSO-Host für WordPress-Client-Sites. Host und Clients können jeweils eigenständige WordPress-Installationen oder Multisite-Installationen sein. Die Sites müssen weder dieselbe Datenbank noch dieselbe Domain verwenden.

## Voraussetzungen

- PHP 7.3 oder neuer
- HTTPS auf dem SSO-Host und jeder Client-Site
- AHX WP SSO auf Host und Clients installiert
- Bei Multisite: Plugin netzwerkweit aktivieren und die SSO-Einstellungen auf der Site vornehmen, die als Host beziehungsweise Client dienen soll
- Jedes Benutzerkonto muss auf dem Host und jeder Client-Site bereits vorhanden sein

## Einrichtung

### 1. SSO-Host einrichten

1. Plugin im WordPress der dedizierten SSO-Site aktivieren.
2. Unter **Einstellungen → AHX WP SSO** die Betriebsart **Dedizierter SSO-Host** speichern.
3. Für jede Client-Site eine Registrierung anlegen. Die Callback-URL wird in Schritt 2 auf der Client-Site angezeigt. Sie muss vollständig und exakt mit HTTPS eingetragen werden.
4. Das nach dem Anlegen einmalig angezeigte Client-Secret sicher aufbewahren. Es wird nicht im Klartext in der Datenbank gespeichert und kann später nicht erneut angezeigt werden.

Registrierte Clients können in der Liste widerrufen werden. Nach dem Widerruf sind keine neuen Anmeldungen dieses Clients mehr möglich.

In der Client-Liste kann die Anmeldedarstellung pro Client angepasst werden: Anzeigename, HTTPS-Logo-URL und Akzentfarbe. Bei einem Anmeldeversuch wird die Host-Anmeldeseite passend zum Client gestaltet. Ist am Host bereits ein Benutzer angemeldet, erscheint stattdessen eine gestaltete Bestätigung mit „Weiter“ und einer Option, das Konto zu wechseln. Das Passwort wird weiterhin ausschließlich auf der SSO-Host-Seite eingegeben.

### SSO-Dashboard

Im Host-Betrieb erscheint unter **Einstellungen → SSO Dashboard** eine Übersicht mit Betriebsparametern, Endpunkt-URLs, registrierten Clients und Client-Sitzungen. Pro Sitzung werden Benutzer, Client-Site, Status, Beginn, letzter bestätigter Aufruf, Ablaufzeit, die IP-Adresse und der Browser/User-Agent der zugehörigen Host-Sitzung sowie eine gekürzte Sitzungskennung angezeigt. Client-Secrets und Sitzungstoken werden nicht dargestellt.

Eine Sitzung zählt als aktiv, wenn die Client-Sitzung nicht abgemeldet oder widerrufen wurde, die zugehörige Host-Sitzung noch gültig ist und die registrierte Ablaufzeit noch nicht erreicht wurde. Der Host aktualisiert „Zuletzt bestätigt“ bei den Sitzungsprüfungen der Client-Site. Die Tabelle und deren Sitzungszähler berücksichtigen bis zu 500 zuletzt aktualisierte Einträge. IP-Adresse und Browser/User-Agent stammen von der Host-Sitzung, nicht von einer direkten Verbindung zur Client-Site.

### 2. Client-Site einrichten

1. Plugin auf der Client-Site aktivieren.
2. Unter **Einstellungen → AHX WP SSO** die Betriebsart **Client-Site** auswählen.
3. HTTPS-URL des dedizierten Hosts sowie Client-ID und Client-Secret aus der Host-Registrierung eintragen und speichern.
4. Die auf der Einstellungsseite angezeigte Callback-URL muss der URL entsprechen, die für die Client-ID am Host registriert wurde.

Ab dann leitet der Login einer nicht angemeldeten Client-Site zum zentralen Host weiter. Nach erfolgreicher Anmeldung wird ein kurzlebiger, einmal nutzbarer Code zur registrierten Client-URL zurückgegeben. Passwort und Client-Secret werden nicht im Browser zwischen den Sites übertragen; der Code-Austausch erfolgt serverseitig über HTTPS und ist mit PKCE abgesichert.

## Benutzer, Rollen und Berechtigungen

Der Host meldet die E-Mail-Adresse des angemeldeten Kontos. Der Client ordnet sie einer lokalen E-Mail-Adresse zu, die nach Entfernen umgebender Leerzeichen und ohne Beachtung der Groß-/Kleinschreibung übereinstimmt. Es werden keine lokalen Konten automatisch erstellt. Fehlt das lokale Konto oder stimmt die E-Mail-Adresse nicht überein, wird die Anmeldung abgelehnt.

Die Authentifizierung über den Host verleiht keine zusätzlichen Rechte. Benutzerrollen, Capabilities und Site-Berechtigungen werden ausschließlich durch das lokale Benutzerkonto auf der jeweiligen Client-Site bestimmt. Ein gültig angemeldeter Nutzer kann daher weiterhin von Aktionen ausgeschlossen werden, wenn seine lokale Rolle oder Capability dies nicht erlaubt. Das Plugin verändert keine Rollen.

Im Betriebsmodus **Client-Site** sind lokale Passwortanmeldungen deaktiviert. Bestehende Sitzungen, die nicht über den SSO-Host angelegt wurden, werden abgewiesen. Stelle vor dem Aktivieren sicher, dass das lokale Administratorkonto auf der Client-Site dieselbe E-Mail-Adresse wie sein Host-Konto hat und dass du HTTPS-Zugriff auf beide Sites hast.

## Break-Glass-Notfallzugang

Damit bei einem Ausfall des Hosts weiterhin eine Anmeldung möglich ist, kann die Client-Administration unter **Einstellungen → AHX WP SSO → Break-Glass-Notfallzugang** gezielt lokale Benutzerkonten freigeben.

Wähle die gewünschten lokalen Konten aus und speichere anschließend die Einstellungen. Die Liste wird pro Client-Site geführt.

- Nur die ausgewählten lokalen Benutzer-IDs dürfen bei Nichterreichbarkeit des Hosts ihr lokales WordPress-Passwort verwenden. Alle anderen Konten benötigen weiterhin den SSO-Host.
- Der Client prüft den Host über den dedizierten Health-Endpunkt. Eine erfolgreiche HTTP-Antwort unter 500 gilt als Erreichbarkeit; Verbindungs-, DNS-, TLS- und Serverfehler lösen den Notfallmodus aus.
- Die lokale Notfallsitzung funktioniert nur, solange der Host nicht erreichbar ist. Sobald der Host wieder antwortet, wird sie beim nächsten Seitenaufruf beendet und der Benutzer muss sich zentral anmelden.
- Eine Health-Prüfung wird für höchstens fünf Sekunden zwischengespeichert. Der erste fehlgeschlagene Aufruf kann bis zu drei Sekunden dauern.
- Freigegebene Benutzer behalten ausschließlich ihre lokalen Rollen und Berechtigungen. Verwende dafür nach Möglichkeit dedizierte Administratorkonten, einzigartige starke Passwörter und MFA; schränke den Login zusätzlich per VPN oder IP-Regel ein.
- Richte die Freigabe vor einem Ausfall ein und teste den Notfallzugang kontrolliert. Ein nicht erreichbarer Health-Endpunkt, einschließlich eines TLS-Zertifikatsfehlers, wird wie ein Host-Ausfall behandelt.

Der Break-Glass-Zugang ist bewusst eine lokale Authentifizierungsausnahme für eine eng begrenzte Kontenliste. Wer Zugriff auf ein solches lokales Passwort erhält, kann sich während des Host-Ausfalls unabhängig vom zentralen Konto anmelden. Schütze und überprüfe die freigegebenen Konten daher besonders sorgfältig.

## Abmeldung

Die WordPress-Symbolleiste bietet drei Abmeldearten. Der normale WordPress-Abmeldelink entspricht standardmäßig **Alle Sites abmelden**.

- **Nur diese Site abmelden** beendet nur die lokale Client-Sitzung. Die zentrale SSO-Sitzung und Sitzungen auf anderen Sites bleiben bestehen.
- **Alle Sites abmelden** widerruft die zugehörige SSO-Sitzungsgruppe. Andere Clients erkennen den Widerruf bei ihrer nächsten Sitzungsprüfung; die Prüfung wird für bis zu 15 Sekunden zwischengespeichert. Andere Geräte bleiben angemeldet.
- **Alle Geräte abmelden** widerruft alle SSO-Sitzungen dieses Kontos sowie die WordPress-Sitzungen auf dem Host. Clients erkennen den Widerruf bei ihrer nächsten Sitzungsprüfung.

Für normale SSO-Sitzungen müssen Client-Sites den Host für die laufende Sitzungsprüfung erreichen können. Ist der Host nicht erreichbar und gibt es keine noch gültige Zwischenspeicherung, wird der Zugriff aus Sicherheitsgründen verweigert. Der Break-Glass-Zugang ist die eng begrenzte Ausnahme.

## Sicherheit und Betrieb

- Registriere nur vertrauenswürdige Client-Sites und schütze das Client-Secret wie ein Passwort.
- Verwende auf allen Sites gültige TLS-Zertifikate. HTTP wird für den Anmelde- und Abmeldefluss abgelehnt.
- Die Autorisierungscodes sind an Client, Callback-URL und PKCE-Verifier gebunden, nur einmal nutzbar und fünf Minuten gültig.
- Lokale WordPress-Sitzungen bleiben den lokalen Benutzerkonten zugeordnet. Wird ein lokales Konto gesperrt oder gelöscht, kann es sich auf dieser Client-Site nicht mehr anmelden.
- Der Plugin-Modus **Deaktiviert** lässt die normale WordPress-Anmeldung unverändert.
