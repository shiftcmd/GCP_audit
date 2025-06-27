#!/usr/bin/env python3
"""
GCP Infrastructure Rollback Script
Uses audit reports to rollback GCP project configurations.

This script can restore:
- IAM policies and bindings
- Service accounts and keys
- Firewall rules
- Enabled/disabled APIs
- Basic resource configurations
"""

import json
import datetime
import argparse
from typing import Dict, List, Any
from google.cloud import resourcemanager_v3  # type: ignore
from google.cloud import iam_v1  # type: ignore
from google.cloud import compute_v1  # type: ignore
from google.oauth2 import service_account  # type: ignore
from googleapiclient.discovery import build  # type: ignore


class GCPRollback:
    def __init__(self, credentials_path=None):
        """Initialize the GCP Rollback tool with optional service account credentials."""
        if credentials_path:
            self.credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            self.credentials = None
        
        # Initialize clients
        self.init_clients()
        
    def init_clients(self):
        """Initialize all necessary GCP client libraries."""
        try:
            self.resource_manager = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            self.iam_client = iam_v1.IAMClient(credentials=self.credentials)
            
            # For APIs that don't have dedicated clients
            self.service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            self.serviceusage = build('serviceusage', 'v1', credentials=self.credentials)
            self.iam_service = build('iam', 'v1', credentials=self.credentials)
            self.compute_service = build('compute', 'v1', credentials=self.credentials)
            
        except Exception as e:
            print(f"Error initializing clients: {e}")
            raise

    def load_audit_report(self, report_path: str) -> Dict:
        """Load audit report from JSON file."""
        try:
            with open(report_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading audit report: {e}")
            raise

    def restore_iam_policy(self, project_id: str, target_policy: Dict, dry_run=True):
        """Restore IAM policy for a project."""
        print(f"{'[DRY RUN] ' if dry_run else ''}Restoring IAM policy for {project_id}")
        
        try:
            if not dry_run:
                resource = f"projects/{project_id}"
                request_body = {
                    'policy': target_policy,
                    'updateMask': 'bindings,etag'
                }
                
                result = self.service.projects().setIamPolicy(
                    resource=resource,
                    body=request_body
                ).execute()
                
                print(f"IAM policy restored for {project_id}")
                return result
            else:
                print(f"Would restore IAM policy with {len(target_policy.get('bindings', []))} bindings")
                
        except Exception as e:
            print(f"Error restoring IAM policy for {project_id}: {e}")
            return None

    def restore_service_accounts(self, project_id: str, target_service_accounts: List[Dict], dry_run=True):
        """Restore service accounts to target state."""
        print(f"{'[DRY RUN] ' if dry_run else ''}Restoring service accounts for {project_id}")
        
        try:
            # Get current service accounts
            parent = f"projects/{project_id}"
            current_request = self.iam_service.projects().serviceAccounts().list(name=parent)
            current_response = current_request.execute()
            current_sas = {sa['email']: sa for sa in current_response.get('accounts', [])}
            
            # Target service accounts
            target_sas = {sa['email']: sa for sa in target_service_accounts}
            
            # Create missing service accounts
            for email, sa_data in target_sas.items():
                if email not in current_sas:
                    if not dry_run:
                        create_request = {
                            'accountId': sa_data['email'].split('@')[0],
                            'serviceAccount': {
                                'displayName': sa_data.get('display_name', ''),
                                'description': sa_data.get('description', '')
                            }
                        }
                        
                        self.iam_service.projects().serviceAccounts().create(
                            name=parent,
                            body=create_request
                        ).execute()
                        
                        print(f"Created service account: {email}")
                    else:
                        print(f"Would create service account: {email}")
            
            # Delete extra service accounts (be careful with this!)
            for email, sa_data in current_sas.items():
                if email not in target_sas and not email.endswith('.gserviceaccount.com'):
                    # Skip default service accounts
                    continue
                    
                if email not in target_sas:
                    if not dry_run:
                        self.iam_service.projects().serviceAccounts().delete(
                            name=sa_data['name']
                        ).execute()
                        
                        print(f"Deleted service account: {email}")
                    else:
                        print(f"Would delete service account: {email}")
                        
        except Exception as e:
            print(f"Error restoring service accounts for {project_id}: {e}")

    def restore_firewall_rules(self, project_id: str, target_firewalls: List[Dict], dry_run=True):
        """Restore firewall rules to target state."""
        print(f"{'[DRY RUN] ' if dry_run else ''}Restoring firewall rules for {project_id}")
        
        try:
            # Get current firewall rules
            current_request = self.compute_service.firewalls().list(project=project_id)
            current_response = current_request.execute()
            current_firewalls = {fw['name']: fw for fw in current_response.get('items', [])}
            
            # Target firewall rules
            target_fw_dict = {fw['name']: fw for fw in target_firewalls}
            
            # Create/update firewall rules
            for name, fw_data in target_fw_dict.items():
                if name not in current_firewalls:
                    if not dry_run:
                        # Create new firewall rule
                        firewall_body = {
                            'name': fw_data['name'],
                            'network': f"projects/{project_id}/global/networks/{fw_data['network']}" if fw_data.get('network') else None,
                            'direction': fw_data.get('direction', 'INGRESS'),
                            'priority': fw_data.get('priority', 1000),
                            'sourceRanges': fw_data.get('source_ranges', []),
                            'targetTags': fw_data.get('target_tags', []),
                            'allowed': [
                                {
                                    'IPProtocol': rule['protocol'],
                                    'ports': rule['ports']
                                } for rule in fw_data.get('allowed', [])
                            ] if fw_data.get('allowed') else [],
                            'denied': [
                                {
                                    'IPProtocol': rule['protocol'],
                                    'ports': rule['ports']
                                } for rule in fw_data.get('denied', [])
                            ] if fw_data.get('denied') else []
                        }
                        
                        self.compute_service.firewalls().insert(
                            project=project_id,
                            body=firewall_body
                        ).execute()
                        
                        print(f"Created firewall rule: {name}")
                    else:
                        print(f"Would create firewall rule: {name}")
                else:
                    # Check if update is needed (simplified comparison)
                    current_fw = current_firewalls[name]
                    if (current_fw.get('priority') != fw_data.get('priority') or
                        set(current_fw.get('sourceRanges', [])) != set(fw_data.get('source_ranges', []))):
                        
                        if not dry_run:
                            # Update existing firewall rule
                            firewall_body = {
                                'priority': fw_data.get('priority', 1000),
                                'sourceRanges': fw_data.get('source_ranges', []),
                                'targetTags': fw_data.get('target_tags', []),
                            }
                            
                            self.compute_service.firewalls().patch(
                                project=project_id,
                                firewall=name,
                                body=firewall_body
                            ).execute()
                            
                            print(f"Updated firewall rule: {name}")
                        else:
                            print(f"Would update firewall rule: {name}")
            
            # Delete extra firewall rules
            for name in current_firewalls:
                if name not in target_fw_dict:
                    if not dry_run:
                        self.compute_service.firewalls().delete(
                            project=project_id,
                            firewall=name
                        ).execute()
                        
                        print(f"Deleted firewall rule: {name}")
                    else:
                        print(f"Would delete firewall rule: {name}")
                        
        except Exception as e:
            print(f"Error restoring firewall rules for {project_id}: {e}")

    def restore_enabled_apis(self, project_id: str, target_apis: List[str], dry_run=True):
        """Restore enabled APIs to target state."""
        print(f"{'[DRY RUN] ' if dry_run else ''}Restoring enabled APIs for {project_id}")
        
        try:
            # Get currently enabled APIs
            parent = f"projects/{project_id}"
            current_request = self.serviceusage.services().list(parent=parent, filter='state:ENABLED')
            current_response = current_request.execute()
            current_apis = {service['config']['name'] for service in current_response.get('services', [])}
            
            target_api_set = set(target_apis)
            
            # Enable missing APIs
            apis_to_enable = target_api_set - current_apis
            for api in apis_to_enable:
                if not dry_run:
                    enable_request = self.serviceusage.services().enable(
                        name=f"projects/{project_id}/services/{api}"
                    )
                    enable_request.execute()
                    print(f"Enabled API: {api}")
                else:
                    print(f"Would enable API: {api}")
            
            # Disable extra APIs (be very careful with this!)
            apis_to_disable = current_apis - target_api_set
            critical_apis = {
                'cloudresourcemanager.googleapis.com',
                'iam.googleapis.com',
                'serviceusage.googleapis.com',
                'logging.googleapis.com',
                'monitoring.googleapis.com'
            }
            
            for api in apis_to_disable:
                if api not in critical_apis:  # Don't disable critical APIs
                    if not dry_run:
                        disable_request = self.serviceusage.services().disable(
                            name=f"projects/{project_id}/services/{api}"
                        )
                        disable_request.execute()
                        print(f"Disabled API: {api}")
                    else:
                        print(f"Would disable API: {api}")
                else:
                    print(f"Skipping critical API: {api}")
                    
        except Exception as e:
            print(f"Error restoring APIs for {project_id}: {e}")

    def rollback_project(self, project_id: str, audit_data: Dict, components=None, dry_run=True):
        """Rollback a project to the state described in audit data."""
        if components is None:
            components = ['iam', 'service_accounts', 'firewalls', 'apis']
        
        print(f"{'=' * 50}")
        print(f"{'[DRY RUN] ' if dry_run else ''}Rolling back project: {project_id}")
        print(f"Components: {', '.join(components)}")
        print(f"Target state from: {audit_data.get('audit_timestamp', 'Unknown')}")
        print(f"{'=' * 50}")
        
        if 'iam' in components and 'iam_policy' in audit_data:
            self.restore_iam_policy(project_id, audit_data['iam_policy'], dry_run)
        
        if 'service_accounts' in components and 'service_accounts' in audit_data:
            self.restore_service_accounts(project_id, audit_data['service_accounts'], dry_run)
        
        if 'firewalls' in components and 'network_info' in audit_data:
            firewalls = audit_data['network_info'].get('firewalls', [])
            self.restore_firewall_rules(project_id, firewalls, dry_run)
        
        if 'apis' in components and 'enabled_apis' in audit_data:
            self.restore_enabled_apis(project_id, audit_data['enabled_apis'], dry_run)
        
        print(f"Rollback {'simulation ' if dry_run else ''}completed for {project_id}")

    def rollback_from_report(self, report_path: str, project_ids=None, components=None, dry_run=True):
        """Rollback projects from an audit report."""
        print("Loading audit report...")
        audit_report = self.load_audit_report(report_path)
        
        projects_data = audit_report.get('projects', {})
        
        if project_ids:
            # Filter to specified projects
            projects_to_rollback = {pid: data for pid, data in projects_data.items() if pid in project_ids}
        else:
            # Rollback all projects in report
            projects_to_rollback = projects_data
        
        print(f"{'[DRY RUN] ' if dry_run else ''}Starting rollback for {len(projects_to_rollback)} projects")
        
        for project_id, audit_data in projects_to_rollback.items():
            if 'error' in audit_data:
                print(f"Skipping {project_id} (audit error: {audit_data['error']})")
                continue
                
            try:
                self.rollback_project(project_id, audit_data, components, dry_run)
            except Exception as e:
                print(f"Error rolling back {project_id}: {e}")


def main():
    """Main function to run the rollback."""
    parser = argparse.ArgumentParser(description='GCP Infrastructure Rollback Tool')
    parser.add_argument('report', help='Path to audit report JSON file')
    parser.add_argument('--credentials', help='Path to service account JSON file')
    parser.add_argument('--projects', nargs='+', help='Specific project IDs to rollback')
    parser.add_argument('--components', nargs='+', 
                       choices=['iam', 'service_accounts', 'firewalls', 'apis'],
                       default=['iam', 'service_accounts', 'firewalls', 'apis'],
                       help='Components to rollback')
    parser.add_argument('--dry-run', action='store_true', default=True,
                       help='Perform a dry run (default: True)')
    parser.add_argument('--execute', action='store_true',
                       help='Actually execute the rollback (overrides --dry-run)')
    
    args = parser.parse_args()
    
    # Determine if this is a dry run
    dry_run = args.dry_run and not args.execute
    
    if not dry_run:
        confirm = input("This will make real changes to your GCP projects. Are you sure? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Rollback cancelled.")
            return 1
    
    try:
        # Initialize rollback tool
        rollback_tool = GCPRollback(credentials_path=args.credentials)
        
        # Execute rollback
        rollback_tool.rollback_from_report(
            report_path=args.report,
            project_ids=args.projects,
            components=args.components,
            dry_run=dry_run
        )
        
    except Exception as e:
        print(f"Error running rollback: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    main()
