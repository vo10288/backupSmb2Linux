# Architettura — Backup Rotazionale v2.0

## Moduli

```
backup_rotazionale.py   Orchestratore: carica config, chiama le fasi in ordine
        │
        ├── backup_core.py        Operazioni di basso livello:
        │                          • mount / umount con retry + backoff
        │                          • LUKS open / close
        │                          • pre-check (ping + smbclient)
        │                          • verifica spazio disco
        │
        ├── backup_rsync.py       Esecuzione rsync:
        │                          • retry configurabile
        │                          • parsing statistiche
        │                          • parallelismo (ThreadPoolExecutor)
        │                          • chiama internamente core + security
        │
        ├── backup_security.py    Sicurezza:
        │                          • hash SHA-256 su campione casuale
        │                          • salvataggio manifest di integrità
        │                          • snapshot sorgente (file count, size, ext)
        │                          • confronto con snapshot precedente
        │                          • blocco se rileva anomalie / ransomware
        │
        ├── backup_retention.py   Retention:
        │                          • snapshot mensili (rsync → partizione dedicata)
        │                          • pulizia automatica mesi vecchi
        │
        ├── backup_notify.py      Notifiche e report:
        │                          • salva report JSON + storico 90gg
        │                          • email SMTP
        │                          • webhook generico (Slack, Teams, Telegram)
        │
        ├── backup_dashboard.py   Dashboard web (Flask):
        │                          • KPI, stato partizioni, storico, dettaglio
        │                          • healthcheck /api/health
        │                          • basic auth
        │
        └── backup_restore.py     CLI interattivo per il ripristino:
                                   • scelta giorno → sorgente → sottocartella
                                   • monta LUKS, mostra albero, rsync restore
```

## Flusso di esecuzione (backup notturno)

```
CRON 01:30
    │
    ▼
┌─ Fase 1: Verifica TUTTE le destinazioni offline
│           Smonta partizioni + chiudi LUKS rimasti aperti
│
├─ Fase 2: Apri LUKS giorno corrente + mount
│           Verifica spazio disco minimo
│
├─ Fase 3: Per ogni sorgente (parallelizzabile):
│   │
│   ├── Pre-check:  ping + smbclient
│   │   └── FAIL → skip sorgente
│   │
│   ├── Mount CIFS (ro, retry con backoff)
│   │   └── FAIL → skip sorgente
│   │
│   ├── Anomaly detection:
│   │   ├── Carica snapshot precedente
│   │   ├── Conta file, dimensione, estensioni
│   │   ├── Cerca estensioni ransomware
│   │   └── Confronta variazione → BLOCCA se anomalo
│   │
│   ├── rsync --delete (retry)
│   │
│   ├── Integrità: hash SHA-256 su campione casuale
│   │
│   └── Umount sorgente CIFS
│
├─ Fase 4: Snapshot mensile (se primo backup del mese)
│           Mount partizione mensile → rsync → umount
│
├─ Fase 5: Smonta destinazione + chiudi LUKS
│           Controllo paranoico: tutto offline
│
└─ Fase 6: Report JSON → email → webhook
```

## Persistenza

| File | Percorso | Contenuto |
|---|---|---|
| Config | `/etc/backup_system/config.yaml` | Tutta la configurazione |
| Credenziali | `/etc/backup_system/creds_*` | user/pass/domain per CIFS |
| LUKS key | `/etc/backup_system/luks.key` | Passphrase crittografia |
| Report | `/var/lib/backup_system/report_*.json` | Report singoli backup |
| Storico | `/var/lib/backup_system/history.json` | Ultimi 90 giorni (sommario) |
| Snapshot | `/var/lib/backup_system/snapshot_*.json` | Stato file per anomaly detection |
| Retention | `/var/lib/backup_system/retention_state.json` | Mappa snapshot mensili |
| Manifest | Nella partizione di backup | Hash file verificati |
| Log | `/var/log/backup_system/backup_*.log` | Log completo per esecuzione |

## Sicurezza — difesa in profondità

1. **Isolamento fisico**: 6 partizioni su 7 sempre smontate
2. **Crittografia**: LUKS impedisce accesso ai dati anche se il disco viene rubato
3. **Sola lettura**: le sorgenti CIFS sono montate `ro`
4. **Anomaly detection**: blocca il backup se la sorgente sembra compromessa
5. **Integrità post-backup**: verifica hash per rilevare corruzione silenziosa
6. **Credenziali protette**: file con permessi 600, mai nel repository
7. **Lock file**: impedisce esecuzioni parallele accidentali
