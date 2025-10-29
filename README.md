# 🚀 SMBOverQUICMonitor


**Développé par**: Ayi NEDJIMI Consultants
**Version**: 1.0

## 📋 Description

SMBOverQUICMonitor est un outil de surveillance en temps réel des sessions SMB over QUIC sous Windows. Il surveille les événements du journal Windows pour détecter les connexions SMB utilisant le protocole QUIC, analyse les certificats TLS, les cipher suites négociés, et identifie les problèmes de sécurité potentiels.

### Fonctionnalités principales

- **Surveillance en temps réel** : Abonnement aux événements Windows SMB Server
- **Analyse de sessions** : SessionID, adresse IP client, utilisateur authentifié
- **Inspection des certificats** : Validation, expiration, sujet du certificat
- **Cipher suites** : Identification des algorithmes de chiffrement négociés
- **Métriques de performance** : Durée de session, octets transférés
- **Alertes automatiques** :
  - Certificats invalides ou expirés
  - Sessions de durée anormalement longue (> 1h par défaut)
- **Export CSV** : Rapport complet avec encodage UTF-8 + BOM
- **Logging détaillé** : Fichier de log dans %TEMP%


## 📌 Prérequis

- **OS** : Windows Server 2022 ou Windows 11 (build 22000+)
- **Privilèges** : Administrateur (requis pour accéder aux journaux système)
- **Fonctionnalités Windows** :
  - SMB over QUIC activé
  - Journalisation SMB Server/Operational activée
- **Compilateur** : Visual Studio 2019/2022 avec SDK Windows 10+


## Compilation

1. Ouvrez **Developer Command Prompt for VS**
2. Naviguez vers le répertoire du projet
3. Exécutez le script de compilation :

```batch
go.bat
```

Le script compile avec les options suivantes :
- `/EHsc` : Gestion des exceptions C++
- `/W4` : Niveau d'avertissement élevé
- `/std:c++17` : Standard C++17
- Libs : `wevtapi.lib`, `crypt32.lib`, `ws2_32.lib`, `comctl32.lib`


# 🚀 Vérifier l'état du journal

# 🚀 Activer si nécessaire

## 🚀 Utilisation

### Lancement

```batch
SMBOverQUICMonitor.exe
```

**Important** : Exécutez en tant qu'administrateur (clic droit → "Exécuter en tant qu'administrateur")

### Interface graphique

L'interface affiche une ListView avec les colonnes suivantes :

| Colonne | Description |
|---------|-------------|
| **SessionID** | Identifiant unique de la session SMB |
| **Client IP** | Adresse IP du client QUIC |
| **Utilisateur** | Compte utilisateur authentifié |
| **Sujet Certificat** | Subject DN du certificat TLS présenté |
| **Cipher Suite** | Algorithme de chiffrement négocié (ex: TLS_AES_256_GCM_SHA384) |
| **Début** | Horodatage de début de session |
| **Octets** | Volume de données transférées |
| **Alertes** | Indicateurs de problèmes détectés |

### Boutons de contrôle

- **Démarrer Surveillance** : Lance la surveillance des événements SMB
- **Arrêter** : Stoppe la surveillance
- **Exporter CSV** : Sauvegarde les données dans un fichier CSV UTF-8
- **Effacer** : Vide la liste des sessions affichées

### Interprétation des alertes

| Alerte | Signification | Action recommandée |
|--------|---------------|-------------------|
| `[CERT INVALIDE]` | Le certificat TLS n'est pas valide | Vérifier la chaîne de confiance |
| `[CERT EXPIRÉ]` | Le certificat a dépassé sa date d'expiration | Renouveler le certificat |
| `[DURÉE LONGUE]` | La session dure plus d'1 heure | Vérifier l'utilisation normale |


## Environnement LAB-CONTROLLED

**AVERTISSEMENT** : Cet outil est destiné **uniquement** à des fins de test, audit et apprentissage dans des environnements contrôlés (laboratoires, réseaux de développement).

### Limitations d'usage

- Ne PAS utiliser en production sans validation approfondie
- Ne PAS surveiller des réseaux sans autorisation écrite
- Respecter les politiques de sécurité et de confidentialité de votre organisation

### Configuration de test recommandée

1. **Environnement** : Machine virtuelle Windows Server 2022
2. **Réseau** : Réseau isolé ou VLAN de test
3. **SMB over QUIC** :
   ```powershell
   # Installer la fonctionnalité SMB over QUIC
   Install-WindowsFeature -Name FS-SMBBW

   # Configurer le certificat
   New-SmbServerCertificateMapping -Name "Test" -Thumbprint <thumbprint> -StoreName My
   ```


## Fichiers de log

Les logs sont créés automatiquement dans :

```
%TEMP%\WinTools_SMBOverQUICMonitor_log.txt
```

Format des entrées :
```
2025-01-15 14:23:45 - Session détectée: SID-1 - 192.168.1.100
2025-01-15 14:23:46 - Certificat validé pour SID-1
2025-01-15 14:24:12 - Export réussi vers: C:\Reports\export.csv
```


## Limitations techniques

1. **Parsing des événements** : L'extraction XML des événements Windows est simplifiée. Pour un usage en production, utiliser un parser XML complet.

2. **Certificats** : La validation de certificat est basique. Elle ne couvre pas tous les cas d'usage (OCSP stapling, CRL avancés).

3. **Performance** : La surveillance génère une charge sur le Event Log. Sur des serveurs très chargés, un filtrage plus précis des EventID peut être nécessaire.

4. **Compatibilité** : Windows Server 2019 et versions antérieures ne supportent pas nativement SMB over QUIC.

5. **Données simulées** : Certaines informations (cipher suite, certificat) sont partiellement simulées dans cette version. L'intégration complète nécessiterait des API SMB internes non documentées.


## 🔧 Dépannage

### Erreur "Impossible d'accéder aux journaux SMB"

**Cause** : Privilèges insuffisants ou journal désactivé

**Solution** :
```powershell
Get-WinEvent -ListLog Microsoft-Windows-SMBServer/Operational

wevtutil sl Microsoft-Windows-SMBServer/Operational /e:true
```

### Aucune session détectée

**Cause** : SMB over QUIC non actif ou aucun trafic

**Solution** :
1. Vérifier que SMB over QUIC est configuré
2. Tester une connexion client :
   ```cmd
   net use Z: \\server.contoso.com\share /TRANSPORT:QUIC
   ```

### Compilation échoue

**Cause** : SDK Windows manquant

**Solution** :
- Installer Windows SDK 10.0.19041.0 ou supérieur via Visual Studio Installer


## 🔒 Sécurité et Éthique

### Utilisation responsable

- **Autorisation** : N'utilisez cet outil que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez une autorisation écrite explicite.
- **Confidentialité** : Les logs peuvent contenir des informations sensibles (noms d'utilisateurs, adresses IP). Protégez-les en conséquence.
- **Conformité** : Assurez-vous de respecter le RGPD et autres réglementations applicables lors de la collecte de données de connexion.

### Déclaration de non-responsabilité

Ce logiciel est fourni "tel quel", sans garantie d'aucune sorte. L'auteur et Ayi NEDJIMI Consultants déclinent toute responsabilité pour tout dommage découlant de l'utilisation de cet outil.


## Support

Pour toute question, suggestion ou rapport de bug :

- **Email** : support@ayinedjimi-consultants.com
- **Documentation** : Consultez la documentation Windows sur SMB over QUIC
- **Communauté** : Forums Microsoft TechCommunity


## 📄 Licence

Copyright (c) 2025 Ayi NEDJIMI Consultants

Cet outil est distribué à des fins éducatives et de recherche. Toute utilisation commerciale nécessite une licence appropriée.

- --

**Développé avec expertise par Ayi NEDJIMI Consultants**
*Solutions Windows avancées pour environnements professionnels*


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>