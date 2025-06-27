# 🍊 Citrus IO - GCP Infrastructure Audit Tool

A comprehensive Google Cloud Platform (GCP) infrastructure auditing tool

```
   _______ __                     ________ 
  / ____(_) /________  _______   /  _/ __ \
 / /   / / __/ ___/ / / / ___/   / // / / /
/ /___/ / /_/ /  / /_/ (__  )  _/ // /_/ / 
\____/_/\__/_/   \__,_|____/  /___/\____/  
```

## ✨ Features

- 🚀 **Auto-discovery**: Automatically finds all accessible GCP projects
- 🔍 **Comprehensive auditing**: Covers IAM, compute, storage, networking, and more
- 📊 **Detailed reporting**: Generates JSON reports with timestamped data
- 📁 **Organized output**: Creates structured audit reports directory

## 🛠️ What Gets Audited

### Project-Level Resources
- ✅ Enabled APIs and services
- ✅ IAM policies and bindings
- ✅ Service accounts and configurations

### Compute Resources
- ✅ Virtual Machine instances
- ✅ Instance metadata and configurations
- ✅ Compute zones and regions

### Storage & Databases
- ✅ Cloud Storage buckets
- ✅ Cloud SQL instances
- ✅ Storage policies and permissions

### Networking
- ✅ VPC networks and subnetworks
- ✅ Firewall rules and priorities
- ✅ Network routing configurations

### Container Services
- ✅ Google Kubernetes Engine (GKE) clusters
- ✅ Node pools and configurations

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- Google Cloud SDK (gcloud)
- GCP project access with appropriate permissions

### Installation

1. **Clone the repository**:
   ```bash
   git clone <your-repo-url>
   cd GCP_audit
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Authenticate with GCP**:
   ```bash
   gcloud auth application-default login
   ```

### Usage

**Audit all accessible projects**:
```bash
python gcp_audit_script.py
```

**Audit specific projects**:
```bash
python gcp_audit_script.py --projects project-1 project-2
```

**Use service account credentials**:
```bash
python gcp_audit_script.py --credentials /path/to/service-account-key.json
```

## 📊 Sample Output

```
[19:10:39] 🚀 Initializing GCP Auditor...
[19:10:39] 🔐 Using Application Default Credentials
[19:10:39] 🔧 Initializing GCP clients...
[19:10:51] ✅ All clients initialized successfully

   _______ __                     ________ 
  / ____(_) /________  _______   /  _/ __ \
 / /   / / __/ ___/ / / / ___/   / // / / /
/ /___/ / /_/ /  / /_/ (__  )  _/ // /_/ / 
\____/_/\__/_/   \__,_|____/  /___/\____/  

[19:10:51] 🚀 Starting GCP Infrastructure Audit...
[19:10:51] 📋 Will audit 3 projects
[19:10:51] 📊 [1/3] Processing project: production-app
[19:10:51] 🔍 Auditing project: production-app
[19:10:51]   🔌 Getting enabled APIs for production-app
[19:10:51]     ✅ Found 25 enabled APIs
[19:10:51]   🔐 Getting IAM policy for production-app
[19:10:52]     ✅ Found 12 IAM bindings
[19:10:52]   💻 Getting compute instances for production-app
[19:10:53]     ✅ Found 5 compute instances
```

## 🔐 Required Permissions

The tool requires the following IAM roles:

### For Read-Only Auditing
```bash
roles/viewer
roles/iam.securityReviewer
roles/serviceusage.serviceUsageViewer
```

### For Organization-Level Access
```bash
roles/resourcemanager.organizationViewer
roles/resourcemanager.folderViewer
```

## 📁 Output Structure

Reports are saved in the `audit_reports/` directory:

```
audit_reports/
└── gcp_audit_report_20241227_191051.json
```

### Report Format
```json
{
  "audit_metadata": {
    "timestamp": "2024-12-27T19:10:51",
    "auditor_version": "1.0.0",
    "projects_audited": 3
  },
  "projects": {
    "project-id": {
      "project_id": "project-id",
      "enabled_apis": [...],
      "iam_policy": {...},
      "service_accounts": [...],
      "compute_instances": [...],
      "storage_buckets": [...],
      "network_info": {...}
    }
  }
}
```

## 🛡️ Security Features

- **Credential Protection**: Never logs or stores credentials
- **Safe Defaults**: Read-only operations by default
- **Error Handling**: Graceful handling of permission errors
- **Audit Trail**: Comprehensive logging of all operations

## 🔧 Configuration

### Environment Variables
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
export GOOGLE_CLOUD_PROJECT=default-project-id
```

### Command Line Options
```bash
python gcp_audit_script.py --help

optional arguments:
  --credentials PATH    Path to service account JSON file
  --projects [PROJECT_IDS ...]  Specific project IDs to audit
  --output FILENAME     Output file name (default: timestamped)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.


--**⚠️ Important**: This tool performs read-only operations by default. Always test in non-production environments first. 