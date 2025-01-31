# Step 1: Create the Project Directory Structure
mkdir -p ~/Snort-Lab/{config,rules,logs,pcap}
cd ~/Snort-Lab

# Step 2: Create README File
cat <<EOL > README.md
# Snort Lab - Intrusion Detection System

This project is a **Snort-based Intrusion Detection System (IDS) lab**, designed to analyze network attacks using **custom detection rules**. It includes a **PCAP file analysis**, **live traffic monitoring**, and **alert generation** for security events.

##  Lab Overview
In this lab, we:
- **Configured Snort** with custom rules to detect specific network activities.
- **Analyzed PCAP files** to identify potential security incidents.
- **Tested live detections** for **ICMP (ping)** and **SSH connection attempts**.
- **Logged and reviewed alerts** for forensic analysis.

## 🚀 How to Run Snort
1️⃣ **Install Snort**
\`\`\`bash
sudo apt update && sudo apt install snort -y
\`\`\`

2️⃣ **Run Snort with Custom Rules**
\`\`\`bash
sudo snort -q -l logs -i lo -A console -c config/snort.conf
\`\`\`

3️⃣ **Run Snort on a PCAP File**
\`\`\`bash
sudo snort -q -l logs -r pcap/Intro_to_IDS.pcap -A console -c config/snort.conf
\`\`\`

## 📢 Sample Detection Rule
\`\`\`bash
alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)
\`\`\`

# Step 3: Create Snort Configuration File
cat <<EOL > config/snort.conf
var HOME_NET any
include rules/local.rules
EOL

# Step 4: Create Custom Snort Rules
cat <<EOL > rules/local.rules
alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)
alert tcp any any -> \$HOME_NET 22 (msg:"SSH Connection Detected"; sid:1000002; rev:1;)
EOL

# Step 5: Create Sample Log File
cat <<EOL > logs/alert.log
07/18-12:52:59.337559  [**] [1:1000002:1] SSH Connection Detected [**] [Priority: 0] {TCP} 10.11.90.211:54334 -> 10.10.161.151:22
07/18-12:53:18.979225  [**] [1:1000001:1] Ping Detected [**] [Priority: 0] {ICMP} 10.11.90.211 -> 10.10.161.151
EOL

# Step 6: Move PCAP File (If Available)
if [ -f /etc/snort/Intro_to_IDS.pcap ]; then
    sudo cp /etc/snort/Intro_to_IDS.pcap pcap/
    echo "PCAP file copied successfully."
else
    echo "PCAP file not found. Please add it manually to the 'pcap/' directory."
fi

echo "✅ Snort Lab Project setup is complete!"
