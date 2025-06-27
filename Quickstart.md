# Set-up: Create the virtual environment
python3 -m venv venv
source venv/bin/activate

# Make sure GCP CLI is installed and authenticated
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-464.0.0-darwin-arm.tar.gz
tar -xf google-cloud-cli-464.0.0-darwin-arm.tar.gz
./google-cloud-sdk/install.sh

# Reconmendation: Install to path
echo 'source ~/google-cloud-sdk/path.bash.inc' >> ~/.bash_profile
source ~/.bash_profile

# Or use Google's interactive script
Go to the official documentation: https://cloud.google.com/sdk/docs/install-sdk#mac

Download the latest .tar.gz (the link on the page will always point to the latest).

Extract it.

Run the ./google-cloud-sdk/install.sh script.
Follow its prompts. It will handle adding to your PATH and setting up shell completion correctly for your specific shell.

# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up authentication
gcloud auth application-default login
# OR use service account key file

# 3. Run audit (captures current state)
python gcp_audit.py --projects [your-project-id]

# 4. Test rollback (dry run - safe preview)
python gcp_rollback.py gcp_audit_report_20241215_120000.json --dry-run

# 5. Execute rollback if needed
python gcp_rollback.py gcp_audit_report_20241215_120000.json --execute
