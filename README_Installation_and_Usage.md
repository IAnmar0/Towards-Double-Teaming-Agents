# Towards-Double-Teaming-Agents

this is a personal repository for our Graduation Project sharing the neccessary file and scritps for review

This README explains how to install, configure, run, and use the full project on their own devices.

The platform connects two main components:

- A **Pentest Agent** that performs an authorized assessment and produces raw logs.
- A **SOC Agent** that analyzes structured findings and generates a final DOCX security report.

> **Legal notice:** Use this project only on systems you own or systems for which you have written authorization. Unauthorized penetration testing may be illegal.

---

# 1. System Architecture

The project requires two Linux machines or virtual machines.

## Machine 1: Pentest / Web Application Machine

This machine runs:

- Flask web interface
- Main orchestration backend
- PentestGPT
- Docker
- Anthropic log-to-JSON parser
- JSON transfer to the SOC machine
- Final report retrieval

## Machine 2: SOC Machine

This machine runs:

- SOC intake workflow
- SOC analysis logic
- Report generator
- JSON, Markdown, and DOCX report storage

The two machines communicate through:

- Tailscale VPN
- SSH
- rsync

The complete workflow is:

```text
User enters target
        ↓
Flask validates target
        ↓
PentestGPT runs inside Docker
        ↓
Raw terminal log is generated
        ↓
Claude converts the log to JSON
        ↓
JSON is transferred to SOC machine
        ↓
SOC Agent analyzes the findings
        ↓
DOCX report is generated
        ↓
Report is returned to Flask machine
        ↓
User downloads the report
```

---

# 2. Minimum Requirements

## Hardware

For each machine:

- 4 CPU cores minimum
- 8 GB RAM minimum
- 50 GB free storage

Recommended:

- 8 CPU cores
- 16 GB RAM
- 100 GB free storage

## Operating System

Recommended:

- Kali Linux
- Ubuntu 22.04 or later

The project is mainly designed for Linux. Windows users should use WSL2 or Linux virtual machines.

## Required Software

Install the following on both machines where applicable:

- Python 3
- Git
- Docker
- Docker Compose
- Tailscale
- OpenSSH
- rsync

---

# 3. Prepare the Pentest / Web Machine

## 3.1 Update the System

```bash
sudo apt update
sudo apt upgrade -y
```

## 3.2 Install Required Packages

```bash
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    docker.io \
    docker-compose-plugin \
    openssh-client \
    rsync \
    curl
```

## 3.3 Enable Docker

```bash
sudo systemctl enable --now docker
```

Add the current user to the Docker group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and log in again, then test:

```bash
docker --version
docker compose version
docker ps
```

---

# 4. Download the Project

Clone the repository:

```bash
git clone <YOUR_PROJECT_REPOSITORY_URL>
cd <YOUR_PROJECT_DIRECTORY>
```

Example:

```bash
git clone https://github.com/USERNAME/PROJECT.git
cd PROJECT
```

Check the project files:

```bash
ls -la
```

The project should include files similar to:

```text
app.py
run_pentest.sh
claude_log_to_json.py
send_json_to_soc.py
requirements.txt
.env.example
.gitignore
```

Rename files if they contain copy suffixes such as `(1)` or `(2)`.

Example:

```bash
mv "app (1).py" app.py
mv "claude_log_to_json (1).py" claude_log_to_json.py
mv "run_soc (2).py" run_soc.py
mv "send_json_to_soc (1).py" send_json_to_soc.py
```

The filenames used by the scripts must match the real filenames.

---

# 5. Create the Python Environment

From inside the project directory:

```bash
python3 -m venv venv
source venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install project requirements:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is unavailable, install the common dependencies:

```bash
pip install \
    flask \
    flask-cors \
    requests \
    python-dotenv \
    anthropic \
    python-docx
```

The virtual environment must be activated whenever the Flask application is started:

```bash
source venv/bin/activate
```

---

# 6. Install PentestGPT

Clone PentestGPT into the user home directory:

```bash
cd ~
git clone <PENTESTGPT_REPOSITORY_URL> PentestGPT
cd PentestGPT
```

Follow the installation instructions provided by the PentestGPT repository.

Confirm that its Docker environment works:

```bash
docker compose up -d
docker ps
```

The expected PentestGPT container name in this project is:

```text
pentestgpt
```

Check it:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

If your container uses another name, update the name inside `run_pentest.sh` and the Flask application.

Stop the environment when needed:

```bash
docker compose down
```

---

# 7. Prepare the SOC Machine

On the SOC machine, update and install required packages:

```bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    openssh-server \
    rsync \
    git
```

Enable SSH:

```bash
sudo systemctl enable --now ssh
```

Check its status:

```bash
sudo systemctl status ssh
```

Create the SOC project directory:

```bash
mkdir -p ~/soc_side
cd ~/soc_side
```

Copy or clone the SOC-side files into this directory.

Create the expected folders:

```bash
mkdir -p \
    samples \
    logs/intake \
    logs/processed \
    logs/failed \
    reports/json \
    reports/md \
    reports/docx
```

Create a Python environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If no SOC requirements file exists:

```bash
pip install \
    python-dotenv \
    python-docx \
    requests \
    anthropic
```

Confirm that the main SOC script exists:

```bash
ls -l ~/soc_side/run_soc.py
```

Also confirm that any imported processing module exists, for example:

```bash
ls -l ~/soc_side/api/process_run.py
```

The SOC-side script will fail if its required `api` package or processing modules are missing.

---

# 8. Configure Tailscale

Install Tailscale on both machines.

On Kali or Ubuntu:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Run this on both machines.

Check the devices:

```bash
tailscale status
```

Record the Tailscale IP of the SOC machine.

From the Pentest machine, test connectivity:

```bash
ping TAILSCALEVPN
```

---

# 9. Configure SSH Between the Machines

On the Pentest machine, generate an SSH key:

```bash
ssh-keygen -t ed25519
```

Press Enter to accept the default path.

Copy the key to the SOC machine:

```bash
ssh-copy-id SOC_USER@SOC_TAILSCALE_IP
```

Test passwordless SSH:

```bash
ssh SOC_USER@SOC_TAILSCALE_IP
```

Test file transfer:

```bash
echo '{"test": true}' > test.json
rsync -av test.json SOC_USER@SOC_TAILSCALE_IP:...../soc_side/samples/
```

On the SOC machine:

```bash
ls -l ~/soc_side/samples/
```

---

# 10. Configure Environment Variables

Create a `.env` file on the Pentest machine:

```bash
cd <YOUR_PROJECT_DIRECTORY>
nano .env
```

Add:

```env
ANTHROPIC_API_KEY=your_anthropic_api_key

APP_API_KEY=optional_backend_api_key

SOC_USER=.....
SOC_HOST=......
SOC_BASE_DIR=...../soc_side
SOC_SAMPLES_DIR=....../soc_side/samples
SOC_REPORTS_DIR=....../soc_side/reports/docx
SOC_RUN_SCRIPT=....../soc_side/run_soc.py

ALLOW_PRIVATE_TARGETS=true
ALLOW_LOOPBACK_TARGETS=false
ALLOW_LINK_LOCAL_TARGETS=false
```

Replace all example values with your real settings.

Load the variables:

```bash
set -a
source .env
set +a
```

Confirm without printing the secret:

```bash
test -n "$ANTHROPIC_API_KEY" && echo "Anthropic key is loaded"
echo "$SOC_USER"
echo "$SOC_HOST"
```

## Important Security Requirement

Never write the real Anthropic API key directly inside Python or Bash code.

Do not do this:

```python
ANTHROPIC_API_KEY = "put your api key here"
```

Use:

```python
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("ANTHROPIC_API_KEY")

if not api_key:
    raise RuntimeError("ANTHROPIC_API_KEY is not configured")
```

Add the following to `.gitignore`:

```gitignore
.env
.env.*
venv/
__pycache__/
*.key
secrets.json
Generated_logs/
reports/
```

---

# 11. Configure Project Paths

Open the Flask application:

```bash
nano app.py
```

Verify that these paths match your actual environment:

```text
PENTEST_SCRIPT
JSON_CONVERTER
GENERATED_LOGS_DIR
REPORT_LOCAL_DIR
SOC_USER
SOC_HOST
SOC_SAMPLES_DIR
SOC_REPORTS_DIR
SOC_RUN_SCRIPT
```

Example expected local paths:

```text
/home/USER/PROJECT/run_pentest.sh
/home/USER/PROJECT/claude_log_to_json.py
/home/USER/PROJECT/Generated_logs
/home/USER/PROJECT/reports
```

Make scripts executable:

```bash
chmod +x run_pentest.sh
chmod +x send_json_to_soc.py
chmod +x claude_log_to_json.py
```

---

# 12. Test Each Component Before Running the Full System

Do not start with the full pipeline immediately. Test every part separately.

## 12.1 Test Flask Dependencies

```bash
source venv/bin/activate
python -c "import flask, requests, dotenv, docx; print('Python dependencies OK')"
```

## 12.2 Test Docker

```bash
docker ps
```

## 12.3 Test PentestGPT

Run only against an authorized lab target:

```bash
bash run_pentest.sh 'authorized_ip'
```

Confirm that the raw log is created inside the container:

```bash
docker exec pentestgpt ls -l /workspace/pentest_full_output.log
```

## 12.4 Test Log Copy

```bash
mkdir -p Generated_logs

docker cp \
    pentestgpt:/workspace/pentest_full_output.log \
    Generated_logs/test.log
```

Check it:

```bash
ls -lh Generated_logs/test.log
```

## 12.5 Test JSON Conversion

```bash
python3 claude_log_to_json.py \
    Generated_logs/test.log \
    Generated_logs/test.json
```

Validate JSON:

```bash
python3 -m json.tool Generated_logs/test.json
```

## 12.6 Test SOC Transfer

```bash
rsync -av \
    Generated_logs/test.json \
    "$SOC_USER@$SOC_HOST:$SOC_SAMPLES_DIR/"
```

## 12.7 Test SOC Processing Manually

From the Pentest machine:

```bash
ssh "$SOC_USER@$SOC_HOST"
```

On the SOC machine:

```bash
cd ~/soc_side
source venv/bin/activate
python3 run_soc.py once samples/test.json
```

The exact command may differ depending on your `run_soc.py` implementation.

Check for a report:

```bash
find ~/soc_side/reports -type f
```

## 12.8 Test Report Retrieval

From the Pentest machine:

```bash
mkdir -p reports

rsync -av \
    "$SOC_USER@$SOC_HOST:$SOC_REPORTS_DIR/" \
    reports/
```

Check:

```bash
find reports -type f
```

Only continue to the full Flask workflow after all individual tests succeed.

---

# 13. Run the Full Project

Return to the project directory:

```bash
cd <YOUR_PROJECT_DIRECTORY>
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

Load environment variables:

```bash
set -a
source .env
set +a
```

Start the Flask application:

```bash
python3 app.py
```

The application should display an address similar to:

```text
http://127.0.0.1:5000
```

To open it from another machine, use:

```text
http://PENTEST_MACHINE_IP:5000
```

The Flask app must be listening on `0.0.0.0` for remote access.

Check the listening port:

```bash
ss -lntp | grep 5000
```

---

# 14. How to Use the Platform

1. Open the Flask web interface.
2. Enter an authorized target IP address or domain.
3. Click the launch button.
4. The backend validates the target.
5. A unique job is created.
6. PentestGPT begins the assessment.
7. The UI displays progress updates.
8. The raw log is collected.
9. The log is converted into structured JSON.
10. The JSON is transferred to the SOC machine.
11. The SOC Agent analyzes the finding.
12. A DOCX report is generated.
13. The report is returned to the backend.
14. The download button becomes available.
15. Download and review the report.

---

# 15. Expected Pipeline Stages

The user interface may display these stages:

```text
pentest_running
securing_log
structuring_findings
transmitting_soc
soc_analysis
fetching_report
completed
failed
```

Meaning:

| Stage | Meaning |
|---|---|
| `pentest_running` | PentestGPT is assessing the target. |
| `securing_log` | The raw log is being copied and cleaned. |
| `structuring_findings` | The log is being converted into JSON. |
| `transmitting_soc` | JSON is being sent to the SOC machine. |
| `soc_analysis` | The SOC Agent is analyzing the findings. |
| `fetching_report` | The DOCX report is being returned. |
| `completed` | The report is ready. |
| `failed` | A pipeline stage encountered an error. |

---

# 16. API Usage

## Start a Job

```bash
curl -X POST http://127.0.0.1:5000/api/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "authorized_ip",
    "mode": "ip"
  }'
```

If backend API authentication is enabled:

```bash
curl -X POST http://127.0.0.1:5000/api/start \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_APP_API_KEY" \
  -d '{
    "target": "authorized_ip",
    "mode": "ip"
  }'
```

## Check Health

```bash
curl http://127.0.0.1:5000/api/health
```

## Check Job Status

```bash
curl http://127.0.0.1:5000/api/status/JOB_ID
```

## Download the Report

```bash
curl -OJ http://127.0.0.1:5000/api/download/JOB_ID
```

---

# 17. Common Problems

## Flask Says the Converter File Is Missing

Check the real filename:

```bash
ls -l
```

Rename it:

```bash
mv "claude_log_to_json (1).py" claude_log_to_json.py
```

Or change the configured path in `app.py`.

## Anthropic Key Is Missing

```bash
set -a
source .env
set +a
```

Then confirm:

```bash
test -n "$ANTHROPIC_API_KEY" && echo "Key loaded"
```

## Docker Permission Denied

```bash
sudo usermod -aG docker "$USER"
```

Then log out and log back in.

## PentestGPT Container Is Not Running

```bash
cd ~/PentestGPT
docker compose up -d
docker ps
```

## SSH Connection Fails

```bash
tailscale status
ping "$SOC_HOST"
ssh "$SOC_USER@$SOC_HOST"
```

## rsync Fails

Check installation on both machines:

```bash
rsync --version
```

Test a manual transfer before using the Flask pipeline.

## SOC Report Is Not Generated

Check:

```bash
ssh "$SOC_USER@$SOC_HOST"
cd ~/soc_side
find logs -type f
find reports -type f
```

Run the SOC script manually and inspect its error output.

## UI Is Stuck

Check the Flask terminal.

Check job status manually:

```bash
curl http://127.0.0.1:5000/api/status/JOB_ID
```

Check:

- PentestGPT container
- Raw log creation
- JSON converter
- SSH connection
- SOC report path

## Report Exists but Download Fails

Verify that the report is inside the configured local report directory and that Flask has read permission:

```bash
ls -l reports/
```

---

# 18. Recommended Deployment Improvements

Before deploying outside a laboratory environment:

- Add user login and role-based access control.
- Use HTTPS for the Flask application.
- Use a production server such as Gunicorn.
- Place Nginx in front of Flask.
- Store secrets in a secrets manager.
- Avoid storing user API keys permanently.
- Add rate limiting.
- Add CSRF protection where required.
- Add audit logs.
- Add request size limits.
- Restrict allowed target ranges.
- Add human approval before exploitation.
- Add container resource limits.
- Run components with least privilege.
- Replace direct SSH orchestration with an authenticated SOC API.
- Add centralized logging and monitoring.

---

# 19. Optional Future API-Key Input Feature

A future version can allow the user to enter their own Anthropic API key through the web interface.

Recommended secure behavior:

1. The user enters the API key in a password-type field.
2. Flask receives the key over HTTPS.
3. The key is stored only in the active job memory.
4. The key is passed to the child process as an environment variable.
5. The key is never written to:
   - Source code
   - Logs
   - JSON findings
   - Job-state files
   - Reports
6. The key is removed from memory after job completion.
7. The key is never committed to Git.

Do not use this feature over plain HTTP in a real deployment.

---

# 20. Project Cleanup

Stop Flask with:

```text
Ctrl+C
```

Stop PentestGPT containers:

```bash
cd ~/PentestGPT
docker compose down
```

Deactivate the Python environment:

```bash
deactivate
```

Remove temporary test artifacts if needed:

```bash
rm -f Generated_logs/test.log
rm -f Generated_logs/test.json
rm -f test.json
```

Do not delete real reports or evidence until they are backed up.

---

# 21. Final Verification Checklist

Before running a real authorized test, verify:

- [ ] Python virtual environment works.
- [ ] Python requirements are installed.
- [ ] Docker works without `sudo`.
- [ ] PentestGPT container starts.
- [ ] Anthropic API key is loaded.
- [ ] No API key is hard-coded.
- [ ] Tailscale connects both machines.
- [ ] SSH works without interactive password prompts.
- [ ] rsync works in both directions.
- [ ] SOC folders exist.
- [ ] SOC processing modules exist.
- [ ] Manual JSON conversion succeeds.
- [ ] Manual SOC report generation succeeds.
- [ ] Flask health endpoint returns successfully.
- [ ] The target is owned or explicitly authorized.
- [ ] The final report download directory is writable.

---

# 22. Academic Project Information

**Project Title:** Towards Double Teaming Agent Based on Large Language Models

**Institution:** Jordan University of Science and Technology

**Faculty:** Faculty of Computer and Information Technology

**Department:** Cybersecurity

**Team Members:**

- Ahmad Jumah
- Anmar Abu Eid
- Abdullah Khasib
- Mohammad Ibrahim

**Supervisor:** Dr. Abdullah S. Alshra’a
