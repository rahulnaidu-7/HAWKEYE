Hawkeye: Malware Detection System

Hawkeye is a lightweight, open-source malware detection and neutralization system built with Python and AI. It leverages the YARA engine for pattern matching to detect threats and uses system-level commands to actively neutralize malicious processes and quarantine files.
Unlike traditional "black box" antiviruses, Hawkeye is fully transparent and customizable, allowing security researchers and administrators to write their own detection rules.

🚀 Key Features

🛡️ Multi-Threaded Scanner: Scans files, folders, or the entire system without freezing the UI.
📝 Integrated Rule Editor: Write, edit, and hot-reload custom YARA rules directly within the app.
⚡ Active Neutralization: Automatically detects running malicious processes, kills them, and locks file permissions.
☣️ Secure Quarantine: Moves threats to a safe, isolated directory and renames them to prevent execution.
📊 Live Activity Log: Real-time visibility into what the engine is scanning and detecting.
🌗 Modern UI: Clean, dark-themed interface built with CustomTkinter.

🛠️ Installation

Prerequisites
  
  Python 3.10 or higher
  pip (Python Package Manager)

1. Clone the Repository

  git clone [https://github.com/yourusername/hawkeye.git](https://github.com/yourusername/hawkeye.git)
  cd hawkeye


2. Install Dependencies

  Install the required Python libraries using pip:

  pip install customtkinter yara-python psutil pillow


Note for Windows Users: If you have trouble installing yara-python, you may need to install the Visual C++ Redistributable or use a pre-compiled wheel.

Run the Application:

    python hawkeye.py

Scanning:

  Click "Scan File" or "Scan Folder" to check specific targets.

  Use "⚡ Full System" for a complete drive scan.

  Editing Rules:

  Navigate to the Editor tab.

  Add your own YARA rules or import .yar files.

  Click Save to hot-reload the engine instantly.

Managing Threats:
  Detected threats are automatically moved to the quarantine folder.

  Go to the Quarantine tab to permanently delete or restore files.

📂 Project Structure

  hawkeye/
  │
  ├── hawkeye.py          # Main application entry point
  ├── user_rules.yar      # Database of active YARA rules
  ├── logo.png            # Application sidebar logo
  ├── logo.ico            # Window title bar icon
  │
  ├── quarantine/         # Isolated storage for detected threats
  │   └── malware.vir     # (Example quarantined file)
  │
  └── README.md           # Documentation


🧪 Testing

  To test the system safely without using real malware:
  
  Create a new text file named test_threat.txt.
  
  Paste the following string inside it:
  
  MALWARE_TEST_SIGNATURE


Open Hawkeye and scan this file.

Result: The system should flag it as a [THREAT], kill any process holding it open, and move it to Quarantine.
