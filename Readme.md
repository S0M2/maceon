# System Monitor & RAM Optimizer

[](https://www.rust-lang.org/)
[](https://opensource.org/licenses/MIT)
[](https://ratatui.rs/)

Une interface terminal (TUI) haute performance pour le monitoring système et l'optimisation des ressources, développée en Rust. Ce dashboard offre une visibilité complète sur la santé de votre machine avec une esthétique "Cyber" moderne.

## Fonctionnalités

### Monitoring Multi-Onglets

Basculez entre quatre vues spécialisées via la touche `TAB` :

  - **Overview** : Tableau de bord global avec jauges CPU/RAM/Swap et historique graphique (Sparklines).
  - **Processus** : Gestionnaire de tâches complet avec tri dynamique (CPU, Mémoire, PID, Nom).
  - **Réseau** : Débit entrant/sortant en temps réel et statistiques par interface.
  - **Stockage** : Analyse détaillée de l'occupation des disques et partitions.

### Cyber-Sentinel & Alertes

  - **Système d'alertes visuel** : Le bandeau de titre clignote en rouge en cas de surcharge CPU (\>85%), RAM critique ou surchauffe thermique.
  - **Thermal Tracking** : Surveillance en temps réel des capteurs de température du SoC (optimisé pour Apple Silicon et x86).
  - **RAM Optimizer** : Algorithme de conseil intégré qui identifie les 5 processus les plus gourmands pour vous aider à libérer de la mémoire.

### Gestion des Processus

  - **Tri intelligent** : Organisez vos processus par consommation de ressources.
  - **Kill switch** : Terminez n'importe quel processus directement depuis l'interface avec la touche `K`.

## Installation & Build

### Prérequis

  - [Rust & Cargo](https://rustup.rs/) (dernière version stable)

### Compilation

```bash
# Cloner le projet
git clone https://github.com/S0M2/System-Monitor.git
cd System-Monitor

# Build en mode release pour des performances optimales
cargo build --release

# Lancer l'outil
./target/release/TOOLS
```

## Raccourcis Clavier

| Touche | Action |
| :--- | :--- |
| `TAB` / `BackTab` | Naviguer entre les onglets |
| `↑` / `↓` | Naviguer dans la liste des processus |
| `K` | Tuer le processus sélectionné |
| `C` | Trier les processus par **CPU** |
| `M` | Trier les processus par **Mémoire** |
| `P` | Trier les processus par **PID** |
| `N` | Trier les processus par **Nom** |
| `Q` | Quitter l'application |

## Sécurité et Performance

  - **Mémoire Sûre** : Développé 100% en Rust pour garantir l'absence de *buffer overflows* et de *segmentation faults*.
  - **Léger** : Utilise `sysinfo` pour un accès bas niveau aux métriques système avec un impact minimal sur les performances.
  - **Pas de Root** : Fonctionne sans privilèges administrateur (sauf pour tuer des processus système protégés).

## Licence

Distribué sous la licence MIT. Voir le fichier `LICENSE` pour plus d'informations.

*Développé avec ❤️ par S0M2.*
