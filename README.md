# mailauthcheck

Analyseur complet SPF / DKIM / DMARC en ligne de commande, écrit en Go pur.

## Fonctionnalités

- **SPF** : lookup DNS brut, vérification pour un couple IP/MAIL FROM, résolution
  récursive complète (flatten) des `include`, `redirect`, `a`, `mx`, `ip4`, `ip6`
  avec respect de la limite de 10 lookups DNS (RFC 7208 §4.6.4)
- **DKIM** : lookup de la clé publique DNS, vérification de signature sur un email
  `.eml` complet
- **DMARC** : lookup + parsing complet (`p`, `sp`, `aspf`, `adkim`, `pct`, `rua`, `ruf`)
- **Alignement DMARC** : calcul SPF/DKIM aligné (relaxed ou strict)
- **Résumé DMARC** : pass/fail global, prise en compte de `p`, `sp`, `pct`, action
  théorique (none / quarantine / reject)
- **Autofill depuis email** : extraction automatique de `From`, `Return-Path`,
  sélecteur DKIM, domaine DKIM, IP cliente depuis un fichier `.eml`
- **Sortie JSON human-readable** (`-json`) et **JSONL** pour SIEM/Loki/Elastic
  (`-jsonl`)
- **Mode permissif** (`-permissive`) : poursuit l'analyse même en cas d'erreurs DNS
  non critiques

## Installation

```sh
go install github.com/vignemail1/mailauthcheck@latest
```

Ou télécharger le binaire depuis les [Releases](https://github.com/vignemail1/mailauthcheck/releases).

## Usage

```
mailauthcheck -domain <domaine> [options]
```

### Options

| Flag | Description | Défaut |
|---|---|---|
| `-domain` | Domaine à analyser **(obligatoire)** | — |
| `-dkim-selector` | Sélecteur DKIM pour le lookup DNS | — |
| `-dkim-d` | Domaine `d=` pour l'alignement DMARC | — |
| `-ip` | IP source à tester pour SPF | — |
| `-mailfrom` | Adresse MAIL FROM pour le test SPF | — |
| `-from` | Adresse `From:` pour l'alignement DMARC | — |
| `-helo` | Nom HELO/EHLO pour SPF | `localhost` |
| `-email` | Chemin vers un fichier `.eml` pour vérification DKIM | — |
| `-autofill-from-email` | Extraire `From`, MAIL FROM, sélecteur/domaine DKIM, IP depuis `-email` | `false` |
| `-flatten` | Résoudre toutes les IP autorisées par SPF | `false` |
| `-json` | Sortie JSON indentée | `false` |
| `-jsonl` | Sortie JSON one-liner (compatible SIEM) | `false` |
| `-permissive` | Ignorer les erreurs DNS non critiques | `false` |

## Exemples

### Analyse DNS simple

```sh
mailauthcheck -domain example.com -dkim-selector default
```

### Analyse complète avec test SPF et alignement

```sh
mailauthcheck \
  -domain example.com \
  -ip 203.0.113.42 \
  -mailfrom bounce@example.com \
  -from "User <user@example.com>" \
  -dkim-selector default \
  -flatten
```

### Vérification depuis un fichier email (autofill)

```sh
mailauthcheck \
  -domain example.com \
  -email /chemin/vers/message.eml \
  -autofill-from-email \
  -flatten \
  -json
```

### Sortie JSONL pour ingestion SIEM / Loki

```sh
mailauthcheck -domain example.com -flatten -jsonl \
  | tee -a /var/log/mailauthcheck.jsonl
```

Ou en pipeline avec `jq` :

```sh
mailauthcheck -domain example.com -json | jq '.dmarc_result'
```

### Mode permissif (ex: DNS partiellement indisponible)

```sh
mailauthcheck -domain example.com -permissive -json
```

## Format JSON de sortie

```json
{
  "timestamp": "2026-03-24T10:00:00Z",
  "domain": "example.com",
  "spf_records": ["v=spf1 include:_spf.example.com -all"],
  "spf_flatten": {
    "networks": [
      { "cidr": "198.51.100.10/32", "source": "_spf.example.com" }
    ],
    "lookup_count": 3,
    "limit_reached": false,
    "unsupported_terms": []
  },
  "spf_check": {
    "ip": "198.51.100.10",
    "mailfrom": "bounce@example.com",
    "helo": "mail.example.com",
    "result": "pass"
  },
  "dkim_dns": {
    "raw": "v=DKIM1; k=rsa; p=...",
    "tags": { "v": "DKIM1", "k": "rsa", "p": "..." }
  },
  "dkim_signatures": [
    { "domain": "example.com", "selector": "default", "valid": true }
  ],
  "dmarc": {
    "raw": "v=DMARC1; p=reject; aspf=s; adkim=s; rua=mailto:dmarc@example.com",
    "policy": "reject",
    "subdomain_policy": "",
    "aspf": "s",
    "adkim": "s",
    "rua": ["mailto:dmarc@example.com"],
    "pct": 100
  },
  "alignment": {
    "from_domain": "example.com",
    "mailfrom_domain": "example.com",
    "dkim_domain": "example.com",
    "aspf": "s",
    "adkim": "s",
    "spf_aligned": true,
    "dkim_aligned": true
  },
  "dmarc_result": {
    "evaluated": true,
    "pass": true,
    "spf_pass": true,
    "spf_aligned": true,
    "dkim_pass": true,
    "dkim_aligned": true,
    "reason": "SPF et DKIM passent et sont alignés",
    "policy": "reject",
    "effective_policy": "reject",
    "pct": 100,
    "action": "none"
  },
  "errors": []
}
```

## Construction locale

```sh
git clone https://github.com/vignemail1/mailauthcheck.git
cd mailauthcheck
go mod tidy
go build -o mailauthcheck .
```

## Dépendances

| Librairie | Rôle |
|---|---|
| `blitiri.com.ar/go/spf` | Evaluation SPF complète (include/redirect/limite RFC) |
| `github.com/emersion/go-dkim` | Vérification signature DKIM |
| `github.com/mjl-/mox/dmarc` | Parsing DMARC |

## Licence

MIT
