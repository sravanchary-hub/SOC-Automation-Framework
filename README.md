# SOC-Automation-Framework

---

# 🚀 SOC WorkFlow  

## 📌 Project Description   
This project demonstrates how to integrate **Shuffle SOAR** with **Wazuh SIEM** and **TheHive** to automate incident response.

✅ **Receiving security alerts** from Wazuh.  
✅ **Enriching alerts** using external threat intelligence (VirusTotal, AbuseIPDB).  
✅ **Creating an incident** in TheHive for case management.  
✅ **Sending notifications** to a Discord channel.  
✅ **(Bonus)** Auto-mitigating threats (e.g., blocking malicious IPs).  

By implementing this SOAR workflow, you can **automate security operations**, reduce response time, and improve efficiency in a **SOC environment**.  

---

## 🔧 Tools Used   
| Tool            | Description |
|----------------|------------|
| **Wazuh SIEM** | Security Information & Event Management (SIEM) solution for threat detection. |
| **TheHive**    | Open-source Security Incident Response Platform (SIRP). |
| **Cortex**     | Analysis and observable enrichment engine used by TheHive and Shuffle. |
| **MISP**       | Threat Intelligence Platform, integrated with Cortex for threat enrichment. |
| **Shuffle**    | Security Orchestration, Automation, and Response (SOAR) platform. |
| **VirusTotal API** | Malware and URL reputation checks (via Cortex analyzer). |
| **AbuseIPDB API**  | IP reputation checks (via Cortex analyzer). |
| **SMTP (Email)**   | Sends alert notifications to specific agents via email. |  

---

## 🛠️ Installation & Setup  

### VPS-1 for Wazuh, Shuffle, Cortex

**Specifications**

- **RAM:** 12GB+
- **HDD:** 120GB+
- **OS:** Ubuntu 24.04 LTS

### **Install Wazuh SIEM**  
Follow the official Wazuh installation guide:  
🔗— [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)  

1. **Update and Upgrade:**
   ```bash
   apt-get update && apt-get upgrade
   ```

2. **Install Wazuh 4.12:**
   ```bash
   curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
   ```

3. **Extract Wazuh Credentials:**
   ```bash
   sudo tar -xvf wazuh-install-files.tar
   ```

4. **Wazuh Dashboard Credentials:**
   - **User:** admin
   - **Password:** ***************

5. **Access Wazuh Dashboard:**
   - Open your browser and go to: `https://<Public IP of Wazuh>`

![image](https://github.com/user-attachments/assets/cdb1b54c-badd-4c1e-876d-107eec169016)


### **Install Shuffle SOAR**  
Run the following commands to install **Shuffle SOAR** on Ubuntu:  
🔗— [Shuffle Installation Guide](https://shuffler.io/docs)  

```bash
# Install Docker if not already installed
sudo apt update && sudo apt install -y docker.io docker-compose

# Enable and start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Clone the Shuffle repository
git clone https://github.com/Shuffle/Shuffle.git
cd Shuffle

# Build and run Shuffle with Docker Compose
sudo docker-compose up -d
```
Access Shuffle Web UI at http://YOUR-IP:3001

<img width="953" alt="image" src="https://github.com/user-attachments/assets/37ef149c-94e8-4fdb-85e6-7d624de8af2d" />


### 🔗-- Cortex Installation Guide --

**Install Java (Required for Elasticsearch)**
```bash
sudo apt update
sudo apt install -y openjdk-11-jdk
java -version
```

**Install Elasticsearch 7.x**
**Cortex supports Elasticsearch 7.x.**

**Add Elasticsearch Repository**
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
```

 **Install Elasticsearch**
```bash
sudo apt update
sudo apt install -y elasticsearch
```

 **Configure Elasticsearch**
```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

 **Example configuration**
```bash
cluster.name: cortex
node.name: cortex-node
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
```

 **Enable and Start Elasticsearch**
```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
```

 **Verify Elasticsearch is Running**
```bash
curl -X GET http://localhost:9200
```

**Install Cortex**

 **Add Cortex Repository**
```bash
wget -qO - https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com cortex-3 main" | sudo tee /etc/apt/sources.list.d/strangebee.list
```

 **Install**
```bash
sudo apt update
sudo apt install -y cortex
```

 **Configure Cortex**
 ```bash
sudo cat /etc/cortex/application.conf
```
 **Generate and Add Secret Key to Configuration File**
```bash
(cat << EOF
 Secret key
 ~~~
 The secret key is used to secure cryptographic functions.
 If you deploy your application to several instances be sure to use the same key!
play.http.secret.key="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)"
_EOF_
) | sudo tee -a /etc/cortex/application.conf
```

 **Enable and Start Cortex**
```bash
sudo systemctl enable cortex
sudo systemctl start cortex
sudo systemctl status cortex
```

 **Access Cortex UI**
 ```bash
URL: http://<your-server-ip>:9001
```

<img width="946" alt="image" src="https://github.com/user-attachments/assets/8c16be52-becc-4d12-8d88-0e1ed0f6fae2" />


**Steps to Set Up Analyzers and Responders**

 #Step (1) Install pip for Python 2Ensure pip for Python 2 is installed:
```bash
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
```

 #Step (2): Get python2
```bash
sudo apt install python2.7
```

 #Step (3) :Dependencies & setup tools: 
 ```bash
sudo apt-get install -y --no-install-recommends python3-pip python2.7-dev python3- pip python3-dev ssdeep libfuzzy-dev libfuzzy2 libimage-exiftool-perl libmagic1 build-essential git libssldev
sudo apt-get install -y --no-install-recommends python3-pip python2.7-dev python3-pip python3-dev ssdeep libfuzzy-dev libfuzzy2 libimage-exiftool-perl libmagic1 build-essential git libssldev
sudo pip install -U pip setuptools && sudo pip3 install -U pip setuptools
```

#Step (4) Clone the Cortex-Analyzers repository to your desired directory:
```bash
git clone https://github.com/TheHive-Project/Cortex-Analyzers
```

**Install Analyzers**:

```bash
for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip install -r $I; done && \
for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip3 install -r $I || true; done
```

 **Modify the application.conf file to point to the analyzers' directory:** 
```bash
/etc/cortex/application.conf

 **analyzer { # Directory that holds analyzers 

path = [ "/path/to/default/analyzers", 
"/path/to/my/own/analyzers" # e.g., /opt/cortex/Cortex-Analyzers/analyzers 
]
}
```
---
### VPS-2 for TheHive, MISP 

**Specifications**

- **RAM:** 12GB+
- **HDD:** 120GB+
- **OS:** Ubuntu 24.04 LTS

### **Install TheHive**  
Follow the official documentation for installing TheHive:  
[TheHive Installation Guide](https://docs.strangebee.com/thehive/installation/)  

1. **Install Dependencies:**
   ```bash
   apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
   ```

2. **Install Java:**
   ```bash
   wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
   echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
   sudo apt update
   sudo apt install java-common java-11-amazon-corretto-jdk
   echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
   export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
   ```

3. **Install Cassandra:**
   ```bash
   wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
   echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
   sudo apt update
   sudo apt install cassandra
   ```

4. **Install ElasticSearch:**
   ```bash
   wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
   sudo apt-get install apt-transport-https
   echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
   sudo apt update
   sudo apt install elasticsearch
   ```

5. **Install TheHive:**
   ```bash
   wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
   echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
   sudo apt-get update
   sudo apt-get install -y thehive
   ```

6. **Default Credentials for TheHive:**
   - **Port:** 9000
   - **Credentials:** 'admin@thehive.local' with a password of 'secret'

![TheHive](https://github.com/user-attachments/assets/22705378-3dae-449f-926c-0c25109a6a40)
 
---

## Configuration for TheHive

### Configure Cassandra

1. **Edit Cassandra Config File:**
   ```bash
   nano /etc/cassandra/cassandra.yaml
   ```

2. **Change Cluster Name:**
   ```yaml
   cluster_name: 'SOAR-Flow'
   ```

3. **Update Listen Address:**
   ```yaml
   listen_address: <public IP of TheHive>
   ```

4. **Update RPC Address:**
   ```yaml
   rpc_address: <public IP of TheHive>
   ```

5. **Update Seed Provider:**
   ```yaml
   - seeds: "<Public IP Of the TheHive>:7000"
   ```

6. **Stop Cassandra Service:**
   ```bash
   systemctl stop cassandra.service
   ```

7. **Remove Old Files:**
   ```bash
   rm -rf /var/lib/cassandra/*
   ```

8. **Restart Cassandra Service:**
   ```bash
   systemctl start cassandra.service
   ```

### Configure ElasticSearch

1. **Edit ElasticSearch Config File:**
   ```bash
   nano /etc/elasticsearch/elasticsearch.yml
   ```

2. **Update Cluster Name and Host:**
   ```yaml
   cluster.name: thehive
   node.name: node-1
   network.host: <Public IP of your TheHive instance>
   http.port: 9200
   discovery.seed_hosts: ["127.0.0.1"]
   cluster.initial_master_nodes: ["node-1"]
   ```

3. **Start ElasticSearch Service:**
   ```bash
   systemctl start elasticsearch
   systemctl enable elasticsearch
   systemctl status elasticsearch
   ```

## Configure TheHive

1. **Ensure Proper Ownership:**
   ```bash
   ls -la /opt/thp
   chown -R thehive:thehive /opt/thp
   ```

2. **Edit TheHive Configuration File:**
   ```bash
   nano /etc/thehive/application.conf
   ```

3. **Update Database and Index Configuration:**
   ```conf
   db.janusgraph {
     storage {
       backend = cql
       hostname = ["<Public IP of TheHive>"]
       cql {
         cluster-name = SOAR-Flow
         keyspace = thehive
       }
     }
   }

   index.search {
     backend = elasticsearch
     hostname = ["<Public IP of TheHive>"]
     index-name = thehive
   }

   application.baseUrl = "http://<Public IP of TheHive>:9000"
   ```

4. **Start TheHive Services:**
   ```bash
   systemctl start thehive
   systemctl enable thehive
   systemctl status thehive
   ```

### ✅ MISP Installation:

```bash
# Please check the installer options first to make the best choice for your install
wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.5/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh

# This will install MISP Core
wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.5/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh -c
```
<img width="958" alt="image" src="https://github.com/user-attachments/assets/177037f0-3262-4cb6-9fa3-f6d7856c033d" />


## 🔄 Workflow - Automating Incident Response  

### 📌 Workflow Overview  
This workflow automates incident response using **Shuffle**, **Wazuh**, **TheHive (with built-in Cortex analyzers and responders)**, and **MISP**.  

1️⃣ **Receive alerts** from **Wazuh SIEM** when suspicious activity is detected.  
2️⃣ **Forward the alert to TheHive**, where **automatic enrichment** (Cortex analyzers like VirusTotal, AbuseIPDB, MISP lookup) is performed within TheHive.  
3️⃣ **Check for duplicate cases** in TheHive; create a **new case** or **update an existing case** with observables and context.  
4️⃣ **Trigger responders (via TheHive)** to take response actions like blocking IPs, disabling users, or quarantining machines if needed.  
5️⃣ **Send an email notification** to the specific **Wazuh agent** owner or SOC team based on the alert source.  

---  

## 📌 Shuffle Workflow Steps  

🔹 **Step 1: Add Wazuh Alert as Trigger**  
- Create a **Webhook Trigger** in Shuffle.  
- Configure **Wazuh** to send alerts to Shuffle via webhook.  

🔹 **Step 2: Parse the Alert**  
- Extract:  
  - **Agent name / Agent ID** (for targeted notifications)  
  - **Source IPs, hashes, domains, URLs** (observables)  
  - **Rule ID, alert description, severity, timestamp**  

🔹 **Step 3: Check for Duplicates in TheHive**  
- Use TheHive's API:  
  - Search existing cases for matching observables or titles.  
- **If case exists:**  
  - **Update the existing case** (add observables, tasks, comments).  
- **If no case exists:**  
  - **Create a new case** with alert details and observables.  

🔹 **Step 4: Trigger TheHive's Automation (Analyzers & Responders)**  
- Once the case is created or updated, TheHive automatically:  
  - Runs configured **analyzers** (VirusTotal, AbuseIPDB, MISP, etc.) on observables.  
  - Executes **responders** if conditions are met (e.g., block IP, disable user, or notify external systems).  

🔹 **Step 5: Send Email Notification**  
- Use Shuffle's **SMTP App** to send an email to:  
  - **The agent owner** (based on agent name from Wazuh alert).  
  - Or the **SOC team email**.  
- Email includes:  
  - Alert details (agent, IPs, observables, rule name)  
  - Link to the TheHive case  
  - Severity level  
  
🔹 **Step 7: (Optional) Auto-Mitigation**  
- If enrichment indicates **high risk**, trigger:  
  - **Block IP** via firewall API, Wazuh active response, or router.  
  - Disable user accounts or isolate machines via EDR/API integrations.

<img width="956" alt="image" src="https://github.com/user-attachments/assets/76d97599-fe80-44f3-94d3-89b8750b5fa6" />

---  

## 🚀 Running the Workflow  

### **Step 1: Configure Wazuh to Send Alerts to Shuffle**  
Edit the Wazuh **ossec.conf** file to send webhook alerts:  
```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://<shuffle-ip>:5001/webhook</hook_url>
  <event_format>json</event_format>
</integration>
```
Restart Wazuh to apply changes:  
```bash
sudo systemctl restart wazuh-manager
```

### **Step 2: Configure TheHive API Key**  
Generate an API key in TheHive and add it to Shuffleâ€™s HTTP Request node.  

### **Step 3: Configure the Cortex Job**
Set the cortex job afer the webhook listener to analyze

### **Step 4: Test the Workflow**  
- Trigger an alert in Wazuh (e.g., Windows audit failure event).  
- Verify the incident is created in TheHive.  
- Check if the alert is sent to Gmail.  

## 📌 Example Output  

✅ **TheHive Incident Created:**  

[INFO] New Incident Created in TheHive:
- Title: Windows audit failure event
- Severity: High
- Source: Wazuh SIEM

---

✅ **Email Notification Sent:**  
Subject: Windows audit failure event

Body:
Hive case like below 

- Alert Name: Windows audit failure event
- Source IP: 192.168.1.100
- Rule ID: 60104
- Severity: High

The case has been created/updated in TheHive.

Check TheHive: http://<thehive-ip>:9000

<img width="494" alt="image" src="https://github.com/user-attachments/assets/6dcc2556-c347-4102-97c5-1e68de79779f" />

---

## 🎯 Future Enhancements  
1. Add More Automated Response Actions
   
🔥 Block IPs on Firewalls:
Integrate with iptables, UFW, or Cloud Firewall APIs (e.g., AWS, Azure, Cloudflare).

🧠 Quarantine Endpoints:
Integrate with Velociraptor, OSQuery, or EDR tools (like Wazuh Active Response or CrowdSec).

🧹 Kill Malicious Processes or Delete Files:
Create a responder that communicates with an endpoint agent to terminate processes or delete malware.

2. Playbook Library
   
Develop a Playbook Repository:
Examples: Phishing, Malware Outbreak, Ransomware, Insider Threat, Brute Force, etc.

Each playbook should include:
Detection → Enrichment → Containment → Notification → Closure

3. Dashboards for SOC Visibility
   
Build custom SOC Dashboards using:
Grafana + ElasticSearch for Wazuh data.

TheHive API to display open cases, severity breakdown, response time, etc.
Shuffle API metrics for automation performance.

4. Incident SLA Tracking
   
Implement SLA timers:
Track time to acknowledge, time to respond, and time to resolve.
Integrate SLA breach alerts into email, Slack, or Discord.

---

## 📜 License  
This project is licensed under the **MIT License**.  

---

## 📬 Contact  

👤 **Author:** Sravanchary  
💻 **GitHub:** [https://github.com/sravanchary1](https://github.com/sravanchary1)  
📧 **LinkedIn:** [https://www.linkedin.com/in/sravan-chary-18b520259](https://www.linkedin.com/in/sravan-chary-18b520259)  

---
