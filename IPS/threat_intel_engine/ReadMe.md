# 🛡️ ThreatMap: Dynamic MITRE ATT&CK & CVE Analyzer

> **A Python-based Threat Intelligence tool that dynamically maps CVEs to MITRE ATT&CK techniques using Natural Language Processing (NLP) and real-time API data.**

---

## 📌 Overview
This tool was built to bridge the gap between Vulnerability Management (CVEs) and Threat Intelligence (MITRE ATT&CK). Unlike standard mappers that rely on hardcoded keyword lists, **ThreatMap** uses a dynamic **TF-IDF style text analysis engine**. It compares vulnerability descriptions against the entire MITRE knowledge base to statistically determine the most likely Tactic, Technique, and Procedure (TTP).

It fulfills the **Bonus Requirements** for the Threat Analysis assignment by providing:
1.  **Live NVD API Integration** (CVSS Scores, Exploit Status).
2.  **Dynamic MITRE Mapping** (No hardcoded rules).
3.  **Threat Actor Profiling** (Reverse lookup: Actor → CVEs).
4.  **Automated Reporting** (JSON output).

---

## 🚀 Key Features

### 1. 🧠 Dynamic "Zero-Rule" Mapping
* Does not use hardcoded dictionaries (e.g., *if "log4j" then "T1190"*).
* Instead, it tokenizes the CVE description and calculates a **Jaccard Similarity Score** against every technique in the MITRE Enterprise Matrix.
* Works on *any* vulnerability, even future ones.

### 2. 🕵️ Threat Actor Reverse Search
* Input a Threat Actor's name (e.g., `APT28`, `Lazarus`).
* The tool scans the group's intelligence profile to find **specific CVEs** they are known to exploit.
* It then auto-fetches the risk details for those specific CVEs.

### 3. 📊 Risk & Exploit Intelligence
* Fetches live **CVSS v3.1** scores.
* Scans NVD references for **Exploit-DB** links or "Exploit" tags to determine if a public exploit exists (`exploit_available: true`).

### 4. 📝 Automated JSON Reporting
* Automatically generates a detailed `.json` report for every analysis.
* Includes the CVE details, mapped techniques, and a list of Threat Actors known to use those techniques.

---

## 🛠️ Installation

### Prerequisites
* Python 3.8+

### Install Dependencies
```bash
pip install requests tabulate colorama
