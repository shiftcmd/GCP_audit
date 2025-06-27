#!/usr/bin/env python3
"""
GCP Infrastructure Audit Tool

This script performs a comprehensive audit of Google Cloud Platform resources
across all accessible projects, generating detailed reports for security review.

Requirements:
    pip install google-cloud-resource-manager google-cloud-iam google-cloud-compute 
    pip install google-cloud-storage google-cloud-container google-cloud-dns 
    pip install google-cloud-monitoring google-cloud-logging google-cloud-firestore 
    pip install google-cloud-pubsub google-cloud-functions google-cloud-run 
    pip install google-cloud-asset google-api-python-client google-auth 
    pip install google-auth-oauthlib google-auth-httplib2 requests python-dateutil
"""

import argparse
import json
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Any
from google.cloud import resourcemanager_v3  # type: ignore
from google.cloud import iam  # type: ignore
from google.cloud import compute_v1  # type: ignore
from google.cloud import storage  # type: ignore
# Attempt to import the generated Cloud SQL Admin GAPIC; fall back to discovery if not available
try:
    from google.cloud import sql_v1  # type: ignore
except ImportError:  # pragma: no cover – library not published on PyPI
    sql_v1 = None  # type: ignore
from google.cloud import container_v1  # type: ignore
from google.cloud import dns  # type: ignore
from google.cloud import monitoring_v3  # type: ignore
from google.cloud import logging_v2  # type: ignore
from google.cloud import firestore  # type: ignore
from google.cloud import pubsub_v1  # type: ignore
from google.cloud import functions_v1  # type: ignore
from google.cloud import run_v2  # type: ignore
from google.cloud import asset_v1  # type: ignore
from google.oauth2 import service_account  # type: ignore
from googleapiclient.discovery import build  # type: ignore

class GCPAuditor:
    def __init__(self, credentials_path=None, verbose=True):
        """Initialize the GCP Auditor with credentials and clients."""
        self.verbose = verbose
        self.log("🚀 Initializing GCP Auditor...")
        
        if credentials_path:
            self.log(f"📋 Loading credentials from: {credentials_path}")
            self.credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            self.log("🔐 Using Application Default Credentials")
            self.credentials = None
        
        self.init_clients()

    def log(self, message: str):
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def init_clients(self):
        """Initialize all necessary GCP client libraries."""
        try:
            self.log("🔧 Initializing GCP clients...")
            self.resource_manager = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            self.iam_client = iam.PoliciesClient(credentials=self.credentials)
            self.compute_client = compute_v1.InstancesClient(credentials=self.credentials)
            self.storage_client = storage.Client(credentials=self.credentials)
            # Cloud SQL Admin – use generated library if present, otherwise discovery
            if sql_v1 is not None:
                self.sql_client = sql_v1.SqlInstancesServiceClient(credentials=self.credentials)
                self.sql_admin_discovery = None
            else:
                self.sql_client = None
                self.sql_admin_discovery = build('sqladmin', 'v1', credentials=self.credentials)
            self.container_client = container_v1.ClusterManagerClient(credentials=self.credentials)
            self.dns_client = dns.Client(credentials=self.credentials)
            self.monitoring_client = monitoring_v3.MetricServiceClient(credentials=self.credentials)
            self.logging_client = logging_v2.Client(credentials=self.credentials)
            self.firestore_client = firestore.Client(credentials=self.credentials)
            self.pubsub_client = pubsub_v1.PublisherClient(credentials=self.credentials)
            self.functions_client = functions_v1.CloudFunctionsServiceClient(credentials=self.credentials)
            self.run_client = run_v2.ServicesClient(credentials=self.credentials)
            self.asset_client = asset_v1.AssetServiceClient(credentials=self.credentials)
            
            # For APIs that don't have dedicated clients
            self.service = build('cloudresourcemanager', 'v1', credentials=self.credentials)
            self.serviceusage = build('serviceusage', 'v1', credentials=self.credentials)
            self.iam_service = build('iam', 'v1', credentials=self.credentials)
            self.log("✅ All clients initialized successfully")
            
        except Exception as e:
            self.log(f"❌ Error initializing clients: {e}")
            raise

    def get_all_projects(self) -> List[Dict]:
        """Retrieve all accessible GCP projects using gcloud CLI."""
        projects = []
        try:
            self.log("🔍 Discovering accessible projects...")
            
            # Use gcloud to list projects since the API requires organization/folder context
            result = subprocess.run(
                ['gcloud', 'projects', 'list', '--format=json'],
                capture_output=True,
                text=True,
                check=True
            )
            
            gcloud_projects = json.loads(result.stdout)
            self.log(f"📋 Found {len(gcloud_projects)} accessible projects via gcloud")
            
            for project in gcloud_projects:
                projects.append({
                    'project_id': project.get('projectId'),
                    'name': project.get('name'),
                    'number': project.get('projectNumber'),
                    'state': project.get('lifecycleState'),
                    'create_time': project.get('createTime'),
                    'labels': project.get('labels', {})
                })
                self.log(f"  📁 {project.get('projectId')} - {project.get('name')}")
                
        except subprocess.CalledProcessError as e:
            self.log(f"❌ Error running gcloud command: {e}")
            self.log("💡 Make sure you're logged in with: gcloud auth login")
        except Exception as e:
            self.log(f"❌ Error getting projects: {e}")
        
        return projects

    def get_enabled_apis(self, project_id: str) -> List[str]:
        """Get all enabled APIs for a project."""
        enabled_apis = []
        try:
            self.log(f"  🔌 Getting enabled APIs for {project_id}")
            parent = f"projects/{project_id}"
            request = self.serviceusage.services().list(parent=parent, filter='state:ENABLED')
            response = request.execute()
            
            for service in response.get('services', []):
                enabled_apis.append(service['config']['name'])
            
            self.log(f"    ✅ Found {len(enabled_apis)} enabled APIs")
                
        except Exception as e:
            self.log(f"    ❌ Error getting enabled APIs for {project_id}: {e}")
        
        return enabled_apis

    def get_iam_policy(self, project_id: str) -> Dict:
        """Get IAM policy for a project."""
        try:
            self.log(f"  🔐 Getting IAM policy for {project_id}")
            resource = project_id  # Just the project ID, not "projects/{project_id}"
            policy = self.service.projects().getIamPolicy(resource=resource, body={}).execute()
            
            bindings_count = len(policy.get('bindings', []))
            self.log(f"    ✅ Found {bindings_count} IAM bindings")
            return policy
        except Exception as e:
            self.log(f"    ❌ Error getting IAM policy for {project_id}: {e}")
            return {}

    def get_service_accounts(self, project_id: str) -> List[Dict]:
        """Get all service accounts for a project."""
        service_accounts = []
        try:
            self.log(f"  👤 Getting service accounts for {project_id}")
            parent = f"projects/{project_id}"
            request = self.iam_service.projects().serviceAccounts().list(name=parent)
            response = request.execute()
            
            for sa in response.get('accounts', []):
                # Get keys for each service account
                keys = []
                try:
                    keys_request = self.iam_service.projects().serviceAccounts().keys().list(
                        name=sa['name']
                    )
                    keys_response = keys_request.execute()
                    keys = keys_response.get('keys', [])
                except:
                    pass
                
                service_accounts.append({
                    'name': sa.get('name'),
                    'email': sa.get('email'),
                    'display_name': sa.get('displayName'),
                    'description': sa.get('description'),
                    'oauth2_client_id': sa.get('oauth2ClientId'),
                    'unique_id': sa.get('uniqueId'),
                    'disabled': sa.get('disabled', False),
                    'keys': keys
                })
            
            self.log(f"    ✅ Found {len(service_accounts)} service accounts")
                
        except Exception as e:
            self.log(f"    ❌ Error getting service accounts for {project_id}: {e}")
        
        return service_accounts

    def get_compute_instances(self, project_id: str) -> List[Dict]:
        """Get all compute instances across all zones."""
        instances = []
        try:
            self.log(f"  💻 Getting compute instances for {project_id}")
            # Get all zones first
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones_request = compute_v1.ListZonesRequest(project=project_id)
            zones = zones_client.list(request=zones_request)
            
            for zone in zones:
                try:
                    request = compute_v1.ListInstancesRequest(
                        project=project_id,
                        zone=zone.name
                    )
                    zone_instances = self.compute_client.list(request=request)
                    
                    for instance in zone_instances:
                        instances.append({
                            'name': instance.name,
                            'zone': zone.name,
                            'machine_type': instance.machine_type.split('/')[-1],
                            'status': instance.status,
                            'creation_timestamp': instance.creation_timestamp,
                            'disks': [{'source': disk.source, 'boot': disk.boot} for disk in instance.disks],
                            'network_interfaces': [
                                {
                                    'network': ni.network,
                                    'subnet': ni.subnetwork,
                                    'internal_ip': ni.network_ip,
                                    'external_ip': ni.access_configs[0].nat_ip if ni.access_configs else None
                                } for ni in instance.network_interfaces
                            ],
                            'tags': list(instance.tags.items) if instance.tags else [],
                            'labels': dict(instance.labels) if instance.labels else {},
                            'service_accounts': [
                                {
                                    'email': sa.email,
                                    'scopes': list(sa.scopes)
                                } for sa in instance.service_accounts
                            ] if instance.service_accounts else []
                        })
                except Exception as e:
                    if "403" not in str(e):  # Only log non-permission errors
                        self.log(f"    ⚠️  Error getting instances in zone {zone.name}: {e}")
            
            self.log(f"    ✅ Found {len(instances)} compute instances")
                    
        except Exception as e:
            if "403" not in str(e) and "SERVICE_DISABLED" not in str(e):
                self.log(f"    ⚠️  Error getting compute instances for {project_id}: {e}")
            else:
                self.log(f"    ℹ️  Compute Engine API not enabled for {project_id}")
        
        return instances

    def get_storage_buckets(self, project_id: str) -> List[Dict]:
        """Get all Cloud Storage buckets."""
        buckets = []
        try:
            self.log(f"  🪣 Getting storage buckets for {project_id}")
            for bucket in self.storage_client.list_buckets():
                bucket_info = {
                    'name': bucket.name,
                    'location': bucket.location,
                    'storage_class': bucket.storage_class,
                    'versioning_enabled': bucket.versioning_enabled,
                    'lifecycle_rules': [],
                    'cors': [],
                    'labels': dict(bucket.labels) if bucket.labels else {},
                    'retention_policy': None,
                    'iam_configuration': None
                }
                
                # Get additional bucket details
                try:
                    bucket.reload()
                    if bucket.lifecycle_rules:
                        bucket_info['lifecycle_rules'] = [rule._properties for rule in bucket.lifecycle_rules]
                    if bucket.cors:
                        bucket_info['cors'] = [cors._properties for cors in bucket.cors]
                    if bucket.retention_policy:
                        bucket_info['retention_policy'] = bucket.retention_policy._properties
                    if bucket.iam_configuration:
                        bucket_info['iam_configuration'] = bucket.iam_configuration._properties
                except:
                    pass
                
                buckets.append(bucket_info)
            
            self.log(f"    ✅ Found {len(buckets)} storage buckets")
                
        except Exception as e:
            if "403" not in str(e) and "SERVICE_DISABLED" not in str(e):
                self.log(f"    ⚠️  Error getting storage buckets for {project_id}: {e}")
            else:
                self.log(f"    ℹ️  Cloud Storage API not enabled for {project_id}")
        
        return buckets

    def get_sql_instances(self, project_id: str) -> List[Dict]:
        """Get all Cloud SQL instances."""
        instances = []
        try:
            self.log(f"  🗄️  Getting SQL instances for {project_id}")
            # Prefer GAPIC if available for richer typing / pagination support
            if self.sql_client is not None:
                request = sql_v1.SqlInstancesListRequest(project=project_id)  # type: ignore[arg-type]
                response = self.sql_client.list(request=request)
                sql_items = response.items if hasattr(response, 'items') else []
            else:
                # Fallback to REST discovery client
                req = self.sql_admin_discovery.instances().list(project=project_id)  # type: ignore[attr-defined]
                resp = req.execute()
                sql_items = resp.get('items', [])

            for instance in sql_items:
                # Field names differ slightly between GAPIC objects and REST dicts; normalise via getattr/ .get()
                def _attr(obj, name, default=None):
                    return getattr(obj, name, obj.get(name, default)) if obj is not None else default

                instances.append({
                    'name': _attr(instance, 'name'),
                    'database_version': _attr(instance, 'database_version'),
                    'region': _attr(instance, 'region'),
                    'state': _attr(_attr(instance, 'state'), 'name', _attr(instance, 'state')),
                    'backend_type': _attr(_attr(instance, 'backend_type'), 'name', _attr(instance, 'backendType')),
                    'instance_type': _attr(_attr(instance, 'instance_type'), 'name', _attr(instance, 'instanceType')),
                    'connection_name': _attr(instance, 'connection_name', _attr(instance, 'connectionName')),
                    'ip_addresses': [
                        {
                            'type': _attr(ip, 'type_', _attr(ip, 'type')) if ip else None,
                            'ip_address': _attr(ip, 'ip_address', _attr(ip, 'ipAddress'))
                        } for ip in _attr(instance, 'ip_addresses', _attr(instance, 'ipAddresses', []))
                    ],
                    'settings': {}
                })
            
            self.log(f"    ✅ Found {len(instances)} SQL instances")
        except Exception as e:
            if "403" not in str(e) and "SERVICE_DISABLED" not in str(e):
                self.log(f"    ⚠️  Error getting SQL instances for {project_id}: {e}")
            else:
                self.log(f"    ℹ️  Cloud SQL API not enabled for {project_id}")
        return instances

    def get_gke_clusters(self, project_id: str) -> List[Dict]:
        """Get all GKE clusters."""
        clusters = []
        try:
            self.log(f"  ⚙️  Getting GKE clusters for {project_id}")
            parent = f"projects/{project_id}/locations/-"
            request = container_v1.ListClustersRequest(parent=parent)
            response = self.container_client.list_clusters(request=request)
            
            for cluster in response.clusters:
                clusters.append({
                    'name': cluster.name,
                    'location': cluster.location,
                    'status': cluster.status.name,
                    'node_count': cluster.current_node_count,
                    'endpoint': cluster.endpoint,
                    'version': cluster.current_master_version,
                    'network': cluster.network,
                    'subnetwork': cluster.subnetwork,
                    'node_pools': [
                        {
                            'name': pool.name,
                            'version': pool.version,
                            'status': pool.status.name,
                            'initial_node_count': pool.initial_node_count,
                            'machine_type': pool.config.machine_type if pool.config else None,
                            'disk_size': pool.config.disk_size_gb if pool.config else None,
                            'oauth_scopes': list(pool.config.oauth_scopes) if pool.config and pool.config.oauth_scopes else []
                        } for pool in cluster.node_pools
                    ] if cluster.node_pools else []
                })
            
            self.log(f"    ✅ Found {len(clusters)} GKE clusters")
                
        except Exception as e:
            if "403" not in str(e) and "SERVICE_DISABLED" not in str(e):
                self.log(f"    ⚠️  Error getting GKE clusters for {project_id}: {e}")
            else:
                self.log(f"    ℹ️  GKE API not enabled for {project_id}")
        
        return clusters

    def get_networks_and_firewalls(self, project_id: str) -> Dict:
        """Get VPC networks and firewall rules."""
        network_info = {'networks': [], 'firewalls': [], 'subnets': []}
        
        try:
            self.log(f"  🌐 Getting network info for {project_id}")
            # Networks
            networks_client = compute_v1.NetworksClient(credentials=self.credentials)
            request = compute_v1.ListNetworksRequest(project=project_id)
            networks = networks_client.list(request=request)
            
            for network in networks:
                network_info['networks'].append({
                    'name': network.name,
                    'auto_create_subnetworks': network.auto_create_subnetworks,
                    'routing_mode': str(network.routing_config.routing_mode) if network.routing_config else None,
                    'description': network.description,
                    'creation_timestamp': network.creation_timestamp
                })
            
            # Firewalls
            firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
            fw_request = compute_v1.ListFirewallsRequest(project=project_id)
            firewalls = firewalls_client.list(request=fw_request)
            
            for firewall in firewalls:
                network_info['firewalls'].append({
                    'name': firewall.name,
                    'network': firewall.network.split('/')[-1] if firewall.network else None,
                    'direction': firewall.direction,
                    'priority': firewall.priority,
                    'source_ranges': list(firewall.source_ranges) if firewall.source_ranges else [],
                    'target_tags': list(firewall.target_tags) if firewall.target_tags else [],
                    'allowed': [
                        {
                            'protocol': rule.ip_protocol,
                            'ports': list(rule.ports) if rule.ports else []
                        } for rule in firewall.allowed
                    ] if firewall.allowed else [],
                    'denied': [
                        {
                            'protocol': rule.ip_protocol,
                            'ports': list(rule.ports) if rule.ports else []
                        } for rule in firewall.denied
                    ] if firewall.denied else []
                })
            
            # Subnets
            regions_client = compute_v1.RegionsClient(credentials=self.credentials)
            regions_request = compute_v1.ListRegionsRequest(project=project_id)
            regions = regions_client.list(request=regions_request)
            
            subnets_client = compute_v1.SubnetworksClient(credentials=self.credentials)
            for region in regions:
                try:
                    subnets_request = compute_v1.ListSubnetworksRequest(
                        project=project_id,
                        region=region.name
                    )
                    subnets = subnets_client.list(request=subnets_request)
                    
                    for subnet in subnets:
                        network_info['subnets'].append({
                            'name': subnet.name,
                            'region': region.name,
                            'network': subnet.network.split('/')[-1] if subnet.network else None,
                            'ip_cidr_range': subnet.ip_cidr_range,
                            'gateway_address': subnet.gateway_address,
                            'private_ip_google_access': subnet.private_ip_google_access,
                            'secondary_ranges': [
                                {
                                    'range_name': range_.range_name,
                                    'ip_cidr_range': range_.ip_cidr_range
                                } for range_ in subnet.secondary_ip_ranges
                            ] if subnet.secondary_ip_ranges else []
                        })
                except Exception as e:
                    if "403" not in str(e):
                        self.log(f"    ⚠️  Error getting subnets in region {region.name}: {e}")
            
            networks_count = len(network_info['networks'])
            firewalls_count = len(network_info['firewalls']) 
            subnets_count = len(network_info['subnets'])
            self.log(f"    ✅ Found {networks_count} networks, {firewalls_count} firewalls, {subnets_count} subnets")
                    
        except Exception as e:
            if "403" not in str(e) and "SERVICE_DISABLED" not in str(e):
                self.log(f"    ⚠️  Error getting network info for {project_id}: {e}")
            else:
                self.log(f"    ℹ️  Compute Engine API not enabled for {project_id}")
        
        return network_info

    def audit_project(self, project_id: str) -> Dict:
        """Perform a comprehensive audit of a single project."""
        self.log(f"🔍 Auditing project: {project_id}")
        
        audit_data = {
            'project_id': project_id,
            'audit_timestamp': datetime.now().isoformat(),
            'enabled_apis': [],
            'iam_policy': {},
            'service_accounts': [],
            'compute_instances': [],
            'storage_buckets': [],
            'sql_instances': [],
            'gke_clusters': [],
            'network_info': {}
        }
        
        # Gather all data
        audit_data['enabled_apis'] = self.get_enabled_apis(project_id)
        audit_data['iam_policy'] = self.get_iam_policy(project_id)
        audit_data['service_accounts'] = self.get_service_accounts(project_id)
        audit_data['compute_instances'] = self.get_compute_instances(project_id)
        audit_data['storage_buckets'] = self.get_storage_buckets(project_id)
        audit_data['sql_instances'] = self.get_sql_instances(project_id)
        audit_data['gke_clusters'] = self.get_gke_clusters(project_id)
        audit_data['network_info'] = self.get_networks_and_firewalls(project_id)
        
        return audit_data

    def generate_report(self, projects_to_audit=None, output_file=None):
        """Generate comprehensive audit report for all or specified projects."""
        # Print ASCII art banner in bright orange using pyfiglet
        bright_orange_color = "\033[38;5;214m"  # Bright orange color code
        reset_color = "\033[0m"  # Reset color
        
        try:
            import pyfiglet
            ascii_text = pyfiglet.figlet_format('Citrus IO', font='slant')
        except ImportError:
            # Fallback ASCII art if pyfiglet is not available
            ascii_text = r"""  _____ _ _                  _____ ___  
 / ____(_) |                |_   _/ _ \ 
| |     _| |_ _ __ _   _ ___  | || | | |
| |    | | __| '__| | | / __| | || | | |
| |____| | |_| |  | |_| \__ \_| || |_| |
 \_____|_|\__|_|   \__,_|___/_____\___/ 
"""
        
        ascii_art = f"{bright_orange_color}{ascii_text}{reset_color}"
        
        print(ascii_art)
        
        # Create audit_reports directory if it doesn't exist
        reports_dir = "audit_reports"
        if not os.path.exists(reports_dir):
            self.log(f"📁 Creating directory: {reports_dir}")
            os.makedirs(reports_dir)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(reports_dir, f"gcp_audit_report_{timestamp}.json")
        else:
            output_file = os.path.join(reports_dir, output_file)
        
        self.log("🚀 Starting GCP Infrastructure Audit...")
        
        # Get all projects if none specified
        if not projects_to_audit:
            all_projects = self.get_all_projects()
            projects_to_audit = [p['project_id'] for p in all_projects]
        
        self.log(f"📋 Will audit {len(projects_to_audit)} projects")
        
        audit_report = {
            'audit_metadata': {
                'timestamp': datetime.now().isoformat(),
                'auditor_version': '1.0.0',
                'projects_audited': len(projects_to_audit)
            },
            'projects': {}
        }
        
        # Audit each project
        for i, project_id in enumerate(projects_to_audit, 1):
            try:
                self.log(f"📊 [{i}/{len(projects_to_audit)}] Processing project: {project_id}")
                audit_report['projects'][project_id] = self.audit_project(project_id)
            except Exception as e:
                self.log(f"❌ Error auditing project {project_id}: {e}")
                audit_report['projects'][project_id] = {
                    'error': str(e),
                    'audit_timestamp': datetime.now().isoformat()
                }
        
        # Save report
        self.log(f"💾 Saving report to: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(audit_report, f, indent=2, default=str)
        
        self.log(f"✅ Audit complete! Report saved to: {output_file}")
        return audit_report


def main():
    """Main function to run the audit."""
    parser = argparse.ArgumentParser(description='GCP Infrastructure Audit Tool')
    parser.add_argument('--credentials', help='Path to service account JSON file')
    parser.add_argument('--projects', nargs='+', help='Specific project IDs to audit')
    parser.add_argument('--output', help='Output file name (default: gcp_audit_report_TIMESTAMP.json)')
    
    args = parser.parse_args()
    
    try:
        # Initialize auditor
        auditor = GCPAuditor(credentials_path=args.credentials)
        
        # Generate report
        auditor.generate_report(
            projects_to_audit=args.projects,
            output_file=args.output
        )
        
    except Exception as e:
        print(f"Error running audit: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    main()
