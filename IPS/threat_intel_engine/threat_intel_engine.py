import requests
import json
import re
import string
import textwrap
import time
from collections import Counter
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colors for the terminal
init(autoreset=True)

class UltimateThreatTool:
    def __init__(self):
        print(f"{Fore.CYAN}{Style.BRIGHT}[*] INITIALIZING THREAT INTELLIGENCE ENGINE...")
        
        # Configuration
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        # Stop words (noise reduction for text analysis)
        self.stop_words = {
            "the", "and", "is", "of", "to", "a", "in", "for", "on", "with", "by", 
            "an", "this", "that", "it", "from", "at", "be", "are", "was", "as", 
            "allows", "user", "attacker", "vulnerability", "issue", "affected", 
            "remote", "code", "execution", "via" # Common but generic terms
        }
        
        # Knowledge Base Storage
        self.kb = {
            "techniques": {}, 
            "actors": {}, 
            "mitigations": {},
            "rel_tech_actor": {},      # TechID -> [ActorIDs]
            "rel_actor_tech": {},      # ActorID -> [TechIDs]
            "rel_tech_mitigation": {}  # TechID -> [MitigationIDs]
        }
        
        self._load_mitre_data()

    def _load_mitre_data(self):
        print(f"{Fore.YELLOW}[-] Downloading & Parsing MITRE Matrix (Dynamic Learning)...")
        try:
            # Fetch official STIX data
            data = requests.get(self.mitre_url).json()
            objects = data.get('objects', [])
            id_map = {} 
            
            # PASS 1: Object Extraction & Indexing
            for obj in objects:
                # Get External MITRE ID (e.g., T1190, G0012)
                ext_id = next((r['external_id'] for r in obj.get('external_references', []) 
                               if r.get('source_name') == 'mitre-attack'), None)
                
                if ext_id:
                    id_map[obj['id']] = ext_id
                    
                    if obj['type'] == 'attack-pattern': # Technique
                        # Create token set for dynamic comparison
                        full_text = (obj.get('name', '') + " " + obj.get('description', '')).lower()
                        self.kb['techniques'][ext_id] = {
                            "name": obj.get('name'),
                            "url": f"https://attack.mitre.org/techniques/{ext_id}",
                            "desc": obj.get('description', ''),
                            "tokens": self._tokenize(full_text)
                        }
                    elif obj['type'] == 'intrusion-set': # Actor
                        self.kb['actors'][ext_id] = {
                            "name": obj.get('name'),
                            "desc": obj.get('description', ''),
                            "aliases": obj.get('aliases', [])
                        }
                    elif obj['type'] == 'course-of-action': # Mitigation
                        self.kb['mitigations'][ext_id] = {
                            "name": obj.get('name')
                        }

            # PASS 2: Relationship Linking
            for obj in objects:
                if obj.get('type') == 'relationship':
                    src = id_map.get(obj.get('source_ref'))
                    tgt = id_map.get(obj.get('target_ref'))
                    
                    if src and tgt:
                        # Actor <--> Technique
                        if obj['relationship_type'] == 'uses':
                            if src in self.kb['actors'] and tgt in self.kb['techniques']:
                                self.kb['rel_tech_actor'].setdefault(tgt, []).append(src)
                                self.kb['rel_actor_tech'].setdefault(src, []).append(tgt)
                        
                        # Mitigation <--> Technique
                        if obj['relationship_type'] == 'mitigates':
                            if src in self.kb['mitigations'] and tgt in self.kb['techniques']:
                                self.kb['rel_tech_mitigation'].setdefault(tgt, []).append(src)

            print(f"{Fore.GREEN}[+] Intelligence Loaded: {len(self.kb['techniques'])} Techniques, {len(self.kb['actors'])} Threat Actors.")

        except Exception as e:
            print(f"{Fore.RED}[!] CRITICAL ERROR LOADING MITRE DATA: {e}")

    def _tokenize(self, text):
        """Breaks text into meaningful keywords (cleaning punctuation/stopwords)."""
        text = text.lower()
        text = text.translate(str.maketrans('', '', string.punctuation))
        words = text.split()
        return {w for w in words if w not in self.stop_words and len(w) > 3}

    def _calculate_relevance(self, cve_tokens, tech_tokens):
        """Calculates similarity score between CVE description and MITRE Technique."""
        intersection = cve_tokens.intersection(tech_tokens)
        return len(intersection) # Simple overlap score

    def get_cve_details(self, cve_id):
        """Fetches Live Data from NVD and checks Exploit-DB references."""
        print(f"{Fore.YELLOW}[-] Querying NVD for {cve_id}...")
        try:
            r = requests.get(self.nvd_api, params={'cveId': cve_id}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data['vulnerabilities']:
                    item = data['vulnerabilities'][0]['cve']
                    
                    # --- INTELLIGENT EXPLOIT CHECK ---
                    # Checks tags AND looks for 'exploit-db' in the URL string
                    exploit_found = False
                    for ref in item.get('references', []):
                        if 'Exploit' in ref.get('tags', []) or 'exploit-db.com' in ref.get('url', ''):
                            exploit_found = True
                            break

                    # Metrics (V3.1 or V3.0)
                    score = 0.0
                    vector = "N/A"
                    severity = "UNKNOWN"
                    
                    metrics = item.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        m = metrics['cvssMetricV31'][0]['cvssData']
                        score = m['baseScore']
                        vector = m['vectorString']
                        severity = m['baseSeverity']
                    elif 'cvssMetricV30' in metrics:
                        m = metrics['cvssMetricV30'][0]['cvssData']
                        score = m['baseScore']
                        vector = m['vectorString']
                        severity = m['baseSeverity']
                    
                    return {
                        "id": item['id'],
                        "description": item['descriptions'][0]['value'],
                        "score": score,
                        "vector": vector,
                        "severity": severity,
                        "exploit_available": exploit_found,
                        "published": item['published'],
                        "last_modified": item['lastModified']
                    }
        except Exception as e:
            print(f"{Fore.RED}[!] API Connection Error: {e}")
        return None

    def map_cve_dynamic(self, cve_desc):
        """Dynamically maps a CVE description to MITRE Techniques."""
        cve_tokens = self._tokenize(cve_desc)
        scores = []

        for tid, tech in self.kb['techniques'].items():
            score = self._calculate_relevance(cve_tokens, tech['tokens'])
            if score > 0:
                scores.append((tid, score))

        # Sort by relevance and take top 5
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:5]

    def save_json_report(self, cve_data, mappings):
        filename = f"{cve_data['id']}_analysis.json"
        
        # Formating exactly as requested
        report = {
            "cve": cve_data,
            "mitre_mappings": mappings
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[+] JSON Report Saved: {filename}")

    # --- MODE 1: CVE ANALYSIS ---
    def run_cve_analysis(self):
        cve_input = input(f"\n{Fore.WHITE}Enter CVE ID (e.g., CVE-2021-44228): ").strip().upper()
        
        cve_data = self.get_cve_details(cve_input)
        if not cve_data:
            print(f"{Fore.RED}[!] CVE Not Found.")
            return

        print(f"\n{Fore.GREEN}=== VULNERABILITY REPORT: {cve_data['id']} ===")
        print(f"CVSS: {cve_data['score']} ({cve_data['severity']})")
        print(f"Exploit Available: {Fore.RED if cve_data['exploit_available'] else Fore.GREEN}{cve_data['exploit_available']}")
        print(f"Description: {cve_data['description'][:100]}...")

        # Dynamic Mapping
        print(f"\n{Fore.YELLOW}--- DYNAMIC MITRE MAPPING ---")
        top_matches = self.map_cve_dynamic(cve_data['description'])
        
        json_mappings = []
        table_data = []

        if top_matches:
            for tid, score in top_matches:
                t_info = self.kb['techniques'][tid]
                
                # Get Actors
                actors = self.kb['rel_tech_actor'].get(tid, [])
                actor_names = [self.kb['actors'][a]['name'] for a in actors]
                
                # Get Mitigation
                mits = self.kb['rel_tech_mitigation'].get(tid, [])
                mit_str = self.kb['mitigations'][mits[0]]['name'] if mits else "Review Security Controls"

                # Add to JSON list
                json_mappings.append({
                    "id": tid,
                    "name": t_info['name'],
                    "url": t_info['url'],
                    "relevance_score": score,
                    "actors": actor_names[:10], # Limit for cleanliness
                    "mitigation": mit_str
                })

                # Add to Table
                table_data.append([
                    tid, 
                    t_info['name'], 
                    f"{score}", 
                    ", ".join(actor_names[:2]) if actor_names else "Generic",
                    mit_str
                ])
            
            print(tabulate(table_data, headers=["ID", "Technique", "Score", "Threat Actors", "Mitigation"], tablefmt="fancy_grid"))
        else:
            print(f"{Fore.RED}[!] No statistical matches found for this description.")

        # Save Output
        self.save_json_report(cve_data, json_mappings)

    # --- MODE 2: THREAT ACTOR ANALYSIS ---
    def run_actor_analysis(self):
        query = input(f"\n{Fore.WHITE}Enter Threat Actor Name (e.g., APT28, Lazarus): ").strip()
        
        target_id = None
        for aid, data in self.kb['actors'].items():
            if query.lower() in data['name'].lower() or query.lower() in [x.lower() for x in data['aliases']]:
                target_id = aid
                break
        
        if not target_id:
            print(f"{Fore.RED}[!] Actor not found.")
            return

        actor = self.kb['actors'][target_id]
        print(f"\n{Fore.GREEN}=== THREAT ACTOR PROFILE: {actor['name']} ===")
        print(f"Aliases: {', '.join(actor['aliases'])}")
        
        # 1. Known Exploited CVEs (Regex scan of description)
        print(f"\n{Fore.YELLOW}--- KNOWN EXPLOITED VULNERABILITIES ---")
        cve_hits = list(set(re.findall(r'CVE-\d{4}-\d+', actor['desc'])))
        
        if cve_hits:
            cve_table = []
            for cve in cve_hits:
                # Re-using our existing NVD fetcher
                details = self.get_cve_details(cve)
                if details:
                    cve_table.append([cve, details['score'], details['severity'], details['description'][:40]])
                else:
                    cve_table.append([cve, "N/A", "Unknown", "Lookup Failed"])
            print(tabulate(cve_table, headers=["CVE ID", "CVSS", "Severity", "Description"], tablefmt="grid"))
        else:
            print(f"{Fore.RED}[!] No specific CVE IDs found in public intelligence profile.")

        # 2. Techniques Used
        print(f"\n{Fore.YELLOW}--- TECHNIQUES & TACTICS ---")
        tech_ids = self.kb['rel_actor_tech'].get(target_id, [])
        tech_table = []
        
        for tid in tech_ids[:10]: # Limit 10
            t_name = self.kb['techniques'][tid]['name']
            tech_table.append([tid, t_name])
            
        print(tabulate(tech_table, headers=["ID", "Technique Used"], tablefmt="fancy_grid"))
        if len(tech_ids) > 10:
            print(f"... and {len(tech_ids)-10} more techniques.")

# --- MAIN MENU ---
if __name__ == "__main__":
    tool = UltimateThreatTool()
    
    while True:
        print(f"\n{Fore.CYAN}=== ULTIMATE THREAT INTELLIGENCE TOOL ===")
        print("1. Analyze CVE (Generate JSON Report)")
        print("2. Analyze Threat Actor (Reverse Lookup)")
        print("3. Exit")
        
        choice = input("Select Option: ").strip()
        
        if choice == '1':
            tool.run_cve_analysis()
        elif choice == '2':
            tool.run_actor_analysis()
        elif choice == '3':
            print("Exiting.")
            break
