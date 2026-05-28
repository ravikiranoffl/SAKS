import argparse
import json
import os
import google.generativeai as genai

def analyze_telemetry(repo_name, pcap_path, log_path):
    print(f"Starting Gemini telemetry analysis for {repo_name}...")
    
    # 1. Configure Gemini API
    api_key = os.environ.get("AI_API_KEY")
    if not api_key:
        print("❌ ERROR: AI_API_KEY environment variable is missing.")
        return
        
    genai.configure(api_key=api_key)

    # 2. Load the System Prompt and Logs
    try:
        with open("core/heuristics/system_prompt.txt", "r") as f:
            system_instruction = f.read()
            
        with open(log_path, "r") as f:
            kernel_logs = f.read()
            
        # In a full build, you'd also parse the PCAP into text here
        telemetry_payload = f"KERNEL LOGS:\n{kernel_logs}"
        
    except FileNotFoundError as e:
        print(f"❌ ERROR: Missing required file - {e}")
        return

    # 3. Initialize the Model with strict JSON output requirements
    model = genai.GenerativeModel(
        model_name="gemini-2.5-flash",
        system_instruction=system_instruction,
        generation_config={"response_mime_type": "application/json"}
    )

    # 4. Ask Gemini to reason over the logs
    print("🧠 Sending telemetry to Gemini for reasoning...")
    try:
        response = model.generate_content(telemetry_payload)
        ai_decision = json.loads(response.text)
        
        print(f"AI Decision: {ai_decision['status']} (Confidence: {ai_decision['confidence_score']}%)")
        print(f"Reasoning: {ai_decision['reasoning']}")
        
        # 5. Take action based on the AI's output
        if ai_decision['status'] == "MALICIOUS":
            for ip in ai_decision.get('extracted_ips', []):
                update_threat_matrix(repo_name, ip)
                
    except Exception as e:
        print(f"❌ ERROR: Gemini API call or parsing failed - {e}")

def update_threat_matrix(repo_name, malicious_ip):
    matrix_path = "threat-matrix/blocklist.json"
    os.makedirs("threat-matrix", exist_ok=True)
    
    if os.path.exists(matrix_path):
        with open(matrix_path, 'r') as f:
            blocklist = json.load(f)
    else:
        blocklist = {"malicious_repositories": [], "blocked_ips": []}
        
    if repo_name not in blocklist["malicious_repositories"]:
        blocklist["malicious_repositories"].append(repo_name)
    if malicious_ip not in blocklist["blocked_ips"]:
        blocklist["blocked_ips"].append(malicious_ip)
        
    with open(matrix_path, 'w') as f:
        json.dump(blocklist, f, indent=4)
    print(f"🚨 Threat Matrix securely updated with {repo_name} and IP {malicious_ip}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--logs", required=True)
    args = parser.parse_args()
    
    analyze_telemetry(args.repo, args.pcap, args.logs)
