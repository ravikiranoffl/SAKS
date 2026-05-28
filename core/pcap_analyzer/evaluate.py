import argparse
import json
import os

def analyze_telemetry(repo_name, pcap_path, log_path):
    print(f"Analyzing telemetry for {repo_name}...")
    
    # In a real environment, you would parse the PCAP and Logs here.
    # We will simulate reading a suspicious log entry:
    suspicious_activity_found = True 
    extracted_malicious_ip = "198.51.100.45"
    
    if suspicious_activity_found:
        print("🛑 AI reasoning complete: Malicious behavior detected (Reverse Shell Attempt).")
        update_threat_matrix(repo_name, extracted_malicious_ip)
    else:
        print("✅ AI reasoning complete: Behavior aligns with expected PoC execution.")

def update_threat_matrix(repo_name, malicious_ip):
    matrix_path = "threat-matrix/blocklist.json"
    
    # Ensure directory exists
    os.makedirs("threat-matrix", exist_ok=True)
    
    # Load existing or create new
    if os.path.exists(matrix_path):
        with open(matrix_path, 'r') as f:
            blocklist = json.load(f)
    else:
        blocklist = {"malicious_repositories": [], "blocked_ips": []}
        
    # Append new threats
    if repo_name not in blocklist["malicious_repositories"]:
        blocklist["malicious_repositories"].append(repo_name)
    if malicious_ip not in blocklist["blocked_ips"]:
        blocklist["blocked_ips"].append(malicious_ip)
        
    # Save back to GitOps state
    with open(matrix_path, 'w') as f:
        json.dump(blocklist, f, indent=4)
    print(f"Threat Matrix updated with {repo_name}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--logs", required=True)
    args = parser.parse_args()
    
    analyze_telemetry(args.repo, args.pcap, args.logs)
