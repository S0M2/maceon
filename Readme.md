# System Monitor & RAM Optimizer

[](https://www.rust-lang.org/)
[](https://opensource.org/licenses/MIT)
[](https://ratatui.rs/)

Une interface terminal (TUI) haute performance pour le monitoring système et l'optimisation des ressources, développée en Rust. Ce dashboard offre une visibilité complète sur la santé de votre machine avec une esthétique "Cyber" moderne.

## Fonctionnalités

### Monitoring Multi-Onglets

Basculez entre sept vues spécialisées via la touche `TAB` :

  - **Overview** : Tableau de bord global avec jauges CPU/RAM/Swap et historique graphique (Sparklines).
  - **Processus** : Gestionnaire de tâches complet avec tri dynamique (CPU, Mémoire, PID, Nom).
  - **Réseau** : Débit entrant/sortant en temps réel et statistiques par interface.
  - **Stockage** : Analyse détaillée de l'occupation des disques et partitions.
  - **Menaces** : Détection d'exfiltration réseau avec géolocalisation IP en temps réel.
  - **Sécurité** : Analyse des processus suspects avec vérification de signature Apple.
  - **Batterie** : Santé batterie macOS et impact énergétique par processus.

### Cyber-Sentinel & Alertes

  - **Système d'alertes visuel** : Le bandeau de titre clignote en rouge en cas de surcharge CPU (>85%), RAM critique ou surchauffe thermique.
  - **Thermal Tracking** : Surveillance en temps réel des capteurs de température du SoC (optimisé pour Apple Silicon et x86).
  - **RAM Optimizer** : Algorithme de conseil intégré qui identifie les 5 processus les plus gourmands pour vous aider à libérer de la mémoire.
  - **Security Alerts** : Alertes en temps réel sur les connexions réseau suspectes et processus non signés.

### Gestion des Processus

  - **Tri intelligent** : Organisez vos processus par consommation de ressources.
  - **Kill switch** : Terminez n'importe quel processus directement depuis l'interface avec la touche `K`.
  - **Signature Verification** : Vérifie automatiquement les signatures de code Apple pour tous les processus.

## Nouvelles Fonctionnalités de Sécurité

### 1. Détection d'Exfiltration Réseau
Analysez toutes les connexions TCP/UDP actives avec géolocalisation IP en temps réel :
- **Identification du pays** : Sait qui parle à votre Mac
- **Détection de risque** : Flag automatique des pays suspects (RU, CN, IR, etc.)
- **Whitelist intelligente** : Marquez les IPs de confiance

### 2. Analyse des Processus Suspects
Chaque processus est évalué pour les indicateurs de malware :
- **Vérification de signature Apple** : [VERIFIED] = signé et notarisé
- **Détection de "dropper"** : Identifie les malwares qui se lancent, font une action, puis disparaissent
- **Score de risque** : 0-100 basé sur signature, lifespan et consommation ressource

### 3. Santé Batterie & Énergie
Optimisez votre batterie MacBook avec :
- **Health % restant** : Santé physique de la batterie
- **Cycle count** : Nombre de charges complètes
- **Impact énergétique** : Quel processus tue votre batterie
- **Temps restant estimé** : Autonomie jusqu'à batterie faible

## Installation & Build

### Prérequis

  - [Rust & Cargo](https://rustup.rs/) (dernière version stable)

### Compilation

```bash
# Cloner le projet
git clone https://github.com/S0M2/maceon.git
cd maceon

# Build en mode release pour des performances optimales
cargo build --release

# Lancer l'outil
./target/release/maceon
```

## Raccourcis Clavier

| Touche | Action |
| :--- | :--- |
| `TAB` / `BackTab` | Naviguer entre les 7 onglets |
| `↑` / `↓` | Naviguer dans la liste des processus (onglet Processus) |
| `K` | Tuer le processus sélectionné (onglet Processus) |
| `C` | Trier les processus par **CPU** |
| `M` | Trier les processus par **Mémoire** |
| `P` | Trier les processus par **PID** |
| `N` | Trier les processus par **Nom** |
| `Q` | Quitter l'application |

## Guide Rapide - Nouvelles Fonctionnalités Sécurité

### Détection d'Exfiltration (Onglet Menaces)
1. Appuyez sur `TAB` 5 fois pour aller à l'onglet **Menaces**
2. Regardez le résumé en haut : Total | Suspectes | Whitelistées
3. Les IPs en **ROUGE** = connexion suspecte (pays risqué, non whitelistée)
4. Les IPs en **VERT** = whitelistées (sûres)
5. Les IPs en **CYAN** = neutres (pays sûr, mais pas whitelistée)

**Que faire ?**
- Connexion suspecte normal ? Whitelistez-la (modifiez `src/network.rs`)
- Connexion suspecte anormale ? Tuez le processus (onglet Processus, `K`)

### Analyse des Processus (Onglet Sécurité)
1. Appuyez sur `TAB` 6 fois pour aller à l'onglet **🔐 Sécurité**
2. Regardez le résumé : Critique | Suspectes | Vérifiées
3. Colonne **✓** montre l'état de signature :
   - `✓` = vert = signé + notarisé par Apple = SÛRE
   - `~` = orange = partiellement signé = À VÉRIFIER
   - `?` = rouge = non signé ou signature invalide = SUSPECT
4. Colonne **Score** : 0-100. >75 = critique (rouge clignotant)
5. Colonne **Durée** : ⚠ <2s = comportement de dropper (malware)

**Que faire ?**
- Score > 75 ? Tuez le processus : `Tab 2` (Processus) → cherchez → `K`
- Durée < 2 sec + haute activité ? Très suspect, tuez-le
- Processus Apple (ex : Finder, Safari) doit avoir ✓ vert

### Batterie & Énergie (Onglet Batterie)
1. Appuyez sur `TAB` 7 fois pour aller à l'onglet ** Batterie**
2. **4 jauges en haut** :
   - CHARGE : % batterie actuelle (⚡ si chargement)
   - SANTÉ : % capacité vs. capacité nominale (important !)
   - Cycles : nombre de charges complètes (usure)
   - Puissance : consommation système en mW
3. **Tableau du bas** : top 20 processus tueurs de batterie
4. **Drain/h** : % batterie consommé par ce processus par heure

**Que faire ?**
- Santé < 50% ? Batterie à remplacer bientôt
- Processus consomme > 50 mW/h ? Fermez-le si possible
- Drain trop élevé ? Réduisez l'utilisation ou branchez le chargeur

## Sécurité et Performance

  - **Mémoire Sûre** : Développé 100% en Rust pour garantir l'absence de *buffer overflows* et de *segmentation faults*.
  - **Léger** : Utilise `sysinfo` pour un accès bas niveau aux métriques système avec un impact minimal sur les performances.
  - **Pas de Root** : Fonctionne sans privilèges administrateur (sauf pour tuer des processus système protégés).

## Licence

Distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus d'informations.

*Développé avec ❤️ par S0M2.*
