import azure.functions as func
import logging
import json
import asyncio
import os
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
import random
import string
import subprocess
import shutil
import platform
import webbrowser
import dns.resolver
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule, NetworkInterface
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import (
    VirtualMachine, HardwareProfile, StorageProfile,
    OSProfile, NetworkProfile, NetworkInterfaceReference,
    VirtualMachineExtension, WindowsConfiguration, SecurityProfile
)
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet
from azure.mgmt.storage import StorageManagementClient
import generate_setup  # Your PowerShell setup generator module
import html_email
import html_email_send

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Constants and configuration
PORTS_TO_OPEN = [22, 80, 443, 3389, 5000, 8000, 47984, 47989, 47990, 47998, 47999, 48000, 48010, 4531, 3475]
GALLERY_IMAGE_RESOURCE_GROUP = 'nvidiaRTX'
GALLERY_NAME = 'rtx2udk'
GALLERY_IMAGE_NAME = 'idtech4rtx'
GALLERY_IMAGE_VERSION = '1.0.2'
OS_DISK_SSD_GB = '256'
WINDOWS_IMAGE_PASSWORD = 'idtechDevKitRTX1!'
RECIPIENT_EMAILS = 'gabzlabs420@gmail.com'

# Console colors for logs (for local testing)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKORANGE = '\033[38;5;214m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

@app.route(route="provision_vm", methods=["POST"])
async def provision_vm(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Parse request body
        req_body = req.get_json()
        
        # Validate required parameters
        required_params = ['domain', 'resource_group', 'location', 'vm_size']
        for param in required_params:
            if param not in req_body:
                return func.HttpResponse(
                    f"Missing required parameter: {param}",
                    status_code=400
                )
        
        # Set parameters with defaults for optional values
        pc_name = ''.join(random.choices(string.ascii_lowercase, k=6))
        domain = req_body.get('domain')
        subdomain = pc_name
        resource_group = req_body.get('resource_group')
        vm_name = req_body.get('vm_name', pc_name)
        location = req_body.get('location')
        vm_size = req_body.get('vm_size')
        
        fqdn_name = domain
        if subdomain:
            subdomain = subdomain.strip().strip('.')
            fqdn_name = f"{subdomain}.{domain}"
        
        # Initialize Azure clients
        credentials = ClientSecretCredential(
            client_id=os.environ['AZURE_APP_CLIENT_ID'],
            client_secret=os.environ['AZURE_APP_CLIENT_SECRET'],
            tenant_id=os.environ['AZURE_APP_TENANT_ID']
        )
        subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']

        compute_client = ComputeManagementClient(credentials, subscription_id)
        storage_client = StorageManagementClient(credentials, subscription_id)
        network_client = NetworkManagementClient(credentials, subscription_id)
        resource_client = ResourceManagementClient(credentials, subscription_id)
        dns_client = DnsManagementClient(credentials, subscription_id)

        # Create resource group
        resource_client.resource_groups.create_or_update(resource_group, {'location': location})
        
        # Create storage account
        storage_account_name = f"{vm_name}{int(time.time()) % 10000}"
        storage_config = await create_storage_account(storage_client, resource_group, storage_account_name, location)
        AZURE_STORAGE_ACCOUNT_KEY = storage_config["AZURE_STORAGE_KEY"]
        AZURE_STORAGE_URL = storage_config["AZURE_STORAGE_URL"]

        # Generate and upload PowerShell script
        ssl_email = os.environ.get('SENDER_EMAIL')
        ps_script = generate_setup.generate_setup(vm_name, fqdn_name, ssl_email)
        
        blob_service_client = BlobServiceClient(account_url=AZURE_STORAGE_URL, credential=credentials)
        container_name = 'vm-startup-scripts'
        blob_name = f"{vm_name}-setup.ps1"
        blob_url_with_sas = await upload_blob_and_generate_sas(blob_service_client, container_name, blob_name, ps_script, AZURE_STORAGE_ACCOUNT_KEY, sas_expiry_hours=2)

        # Create network resources
        vnet_name = f'{vm_name}-vnet'
        subnet_name = f'{vm_name}-subnet'
        network_client.virtual_networks.begin_create_or_update(
            resource_group,
            vnet_name,
            {
                'location': location,
                'address_space': {'address_prefixes': ['10.1.0.0/16']},
                'subnets': [{'name': subnet_name, 'address_prefix': '10.1.0.0/24'}]
            }
        ).result()

        public_ip_name = f'{vm_name}-public-ip'
        public_ip_params = {'location': location, 'public_ip_allocation_method': 'Dynamic'}
        public_ip = network_client.public_ip_addresses.begin_create_or_update(
            resource_group,
            public_ip_name,
            public_ip_params
        ).result()

        # Create NSG with rules
        nsg_name = f'{vm_name}-nsg'
        nsg_params = NetworkSecurityGroup(location=location, security_rules=[])
        nsg = network_client.network_security_groups.begin_create_or_update(resource_group, nsg_name, nsg_params).result()
        
        priority = 100
        for port in PORTS_TO_OPEN:
            rule_name = f'AllowAnyCustom{port}Inbound' 
            rule = SecurityRule(
                name=rule_name,
                access='Allow',
                direction='Inbound',
                priority=priority,
                protocol='*',
                source_address_prefix='*',
                destination_address_prefix='*',
                destination_port_range=str(port),
                source_port_range='*'
            )
            nsg.security_rules.append(rule)
            priority += 1
        network_client.network_security_groups.begin_create_or_update(resource_group, nsg_name, nsg).result()

        # Create NIC
        subnet_id = f'/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet_name}/subnets/{subnet_name}'
        public_ip_id = f'/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/publicIPAddresses/{public_ip_name}'
        
        nic_params = NetworkInterface(
            location=location,
            ip_configurations=[{
                'name': f'{vm_name}-ip-config',
                'subnet': {'id': subnet_id},
                'public_ip_address': {'id': public_ip_id}
            }],
            network_security_group={'id': nsg.id}
        )
        nic = network_client.network_interfaces.begin_create_or_update(resource_group, f'{vm_name}-nic', nic_params).result()

        # Get latest gallery image version
        versions = compute_client.gallery_image_versions.list_by_gallery_image(
            GALLERY_IMAGE_RESOURCE_GROUP,
            GALLERY_NAME,
            GALLERY_IMAGE_NAME
        )
        latest_version = sorted(versions, key=lambda v: v.name)[-1].name
        image_latest_version_id = (
            f"/subscriptions/{subscription_id}/resourceGroups/{GALLERY_IMAGE_RESOURCE_GROUP}"
            f"/providers/Microsoft.Compute/galleries/{GALLERY_NAME}"
            f"/images/{GALLERY_IMAGE_NAME}/versions/{latest_version}"
        )

        # Create VM
        os_disk = {
            'name': f'{vm_name}-os-disk',
            'managed_disk': {'storage_account_type': 'Standard_LRS'},
            'create_option': 'FromImage',
            'disk_size_gb': f"{int(OS_DISK_SSD_GB)}"
        }

        security_profile = SecurityProfile(security_type="TrustedLaunch")
        vm_parameters = VirtualMachine(
            location=location,
            hardware_profile=HardwareProfile(vm_size=vm_size),
            storage_profile=StorageProfile(os_disk=os_disk, image_reference={'id': image_latest_version_id}),
            network_profile=NetworkProfile(network_interfaces=[NetworkInterfaceReference(id=nic.id)]),
            security_profile=security_profile,
            zones=None
        )
        vm = compute_client.virtual_machines.begin_create_or_update(resource_group, vm_name, vm_parameters).result()

        # Wait for VM to initialize
        time.sleep(30)

        # Get public IP
        nic_client = network_client.network_interfaces.get(resource_group, f'{vm_name}-nic')
        public_ip_name = nic_client.ip_configurations[0].public_ip_address.id.split('/')[-1]
        public_ip_info = network_client.public_ip_addresses.get(resource_group, public_ip_name)
        public_ip = public_ip_info.ip_address

        # Configure DNS
        try:
            dns_zone = dns_client.zones.get(resource_group, domain)
        except:
            dns_zone = dns_client.zones.create_or_update(resource_group, domain, {'location': 'global'})

        record_name = subdomain.rstrip('.') if subdomain else '@'
        a_record_set = RecordSet(ttl=3600, a_records=[{'ipv4_address': public_ip}])
        dns_client.record_sets.create_or_update(resource_group, domain, record_name, 'A', a_record_set)

        # Create additional records (pin, drop)
        a_records = ["pin", "drop"]
        for a_record in a_records:
            a_record_set = RecordSet(ttl=3600, a_records=[{'ipv4_address': public_ip}])
            dns_client.record_sets.create_or_update(resource_group, domain, a_record, 'A', a_record_set)

        # Deploy Custom Script Extension
        ext_params = {
            'location': location,
            'publisher': 'Microsoft.Compute',
            'type': 'CustomScriptExtension',
            'type_handler_version': '1.10',
            'settings': {
                'fileUris': [blob_url_with_sas],
                'commandToExecute': f'powershell -ExecutionPolicy Unrestricted -File {blob_name}'
            },
        }
        extension = compute_client.virtual_machine_extensions.begin_create_or_update(
            resource_group,
            vm_name,
            'customScriptExtension',
            ext_params
        ).result(timeout=600)

        # Cleanup temporary storage
        await cleanup_temp_storage_on_success(resource_group, storage_client, storage_account_name, blob_service_client, container_name, blob_name)

        # Prepare response
        response_data = {
            "status": "success",
            "vm_name": vm_name,
            "public_ip": public_ip,
            "domain": fqdn_name,
            "pin_url": f"https://pin.{subdomain}.{domain}",
            "drop_url": f"https://drop.{subdomain}.{domain}",
            "pin_code": "1234"
        }

        # Send email notification
        await send_email_notification(vm_name, public_ip, fqdn_name)

        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error in VM provisioning: {str(e)}")
        await cleanup_resources_on_failure(
            network_client,
            compute_client,
            storage_client,
            blob_service_client,
            container_name,
            blob_name,
            dns_client,
            resource_group,
            domain,
            a_records,
            vm_name=vm_name,
            storage_account_name=storage_account_name
        )
        return func.HttpResponse(
            json.dumps({"status": "error", "message": str(e)}),
            status_code=500,
            mimetype="application/json"
        )

async def send_email_notification(vm_name, public_ip, fqdn_name):
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASS')
    sender_email = os.environ.get('SENDER_EMAIL')
    recipient_emails = [e.strip() for e in RECIPIENT_EMAILS.split(',')]

    html_content = html_email.HTMLEmail(
        ip_address=public_ip,
        background_image_url="https://modwiki.dhewm3.org/images/c/cd/Bump2spec_1_local.png",
        title=f"{vm_name} - Idtech RemoteRTX",
        main_heading=f"{vm_name} - Idtech RemoteRTX",
        main_description="Your virtual machine is ready to play games.",
        youtube_embed_src="https://youtu.be/PeVxO56lCBs",
        image_left_src="",
        image_right_src="",
        logo_src="https://i.postimg.cc/BnsDT6sQ/mohradiant.png",
        company_src="https://i.postimg.cc/25pxqcWZ/powered-by-idtech.png",
        discord_widget_src="https://discord.com/widget?id=1363815250742480927&theme=dark",
        windows_password=WINDOWS_IMAGE_PASSWORD,
        credentials_sunshine="Username: <strong>sunshine</strong><br>Password: <strong>sunshine</strong>",
        form_description="Fill our form, so we can match your team with investors/publishers",
        form_link="https://forms.gle/QgFZQhaehZLs9sySA"
    )

    try:
        html_email_send.send_html_email_smtp(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            sender_email=sender_email,
            recipient_emails=recipient_emails,
            subject=f"Azure VM '{vm_name}' Completed",
            html_content=html_content,
            use_tls=True
        )
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Helper functions (same as before but modified for async)
async def create_storage_account(storage_client, resource_group_name, storage_name, location):
    try:
        poller = storage_client.storage_accounts.begin_create(
            resource_group_name,
            storage_name,
            {
                "sku": {"name": "Standard_LRS"},
                "kind": "StorageV2",
                "location": location,
                "enable_https_traffic_only": True
            }
        )
        storage_account = poller.result()
        
        keys = storage_client.storage_accounts.list_keys(resource_group_name, storage_name)
        storage_key = keys.keys[0].value
        storage_url = f"https://{storage_name}.blob.core.windows.net"

        return {
            "AZURE_STORAGE_URL": storage_url,
            "AZURE_STORAGE_NAME": storage_name,
            "AZURE_STORAGE_KEY": storage_key
        }
    except Exception as e:
        raise Exception(f"Failed to create storage account: {e}")

async def upload_blob_and_generate_sas(blob_service_client, container_name, blob_name, data, storage_key, sas_expiry_hours=1):
    container_client = blob_service_client.get_container_client(container_name)
    try:
        container_client.create_container()
    except:
        pass  # Container likely exists
    
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(data, overwrite=True)
    
    sas_token = generate_blob_sas(
        blob_service_client.account_name,
        container_name,
        blob_name,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=sas_expiry_hours),
        account_key=storage_key
    )
    blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{container_name}/{blob_name}"
    return f"{blob_url}?{sas_token}"

async def cleanup_temp_storage_on_success(resource_group, storage_client, storage_account_name, blob_service_client, container_name, blob_name):
    try:
        container_client = blob_service_client.get_container_client(container_name)
        container_client.delete_blob(blob_name)
        blob_service_client.delete_container(container_name)
        storage_client.storage_accounts.delete(resource_group, storage_account_name)
    except Exception as e:
        logging.warning(f"Could not delete Storage Account '{storage_account_name}': {e}")


async def cleanup_resources_on_failure(network_client, compute_client, storage_client, blob_service_client, container_name, blob_name, dns_client, resource_group, domain, a_records, vm_name, storage_account_name):
    logging.info("Starting cleanup of Azure resources due to failure...")

    # Delete VM
    try:
        vm = compute_client.virtual_machines.get(resource_group, vm_name)
        os_disk_name = vm.storage_profile.os_disk.name
        compute_client.virtual_machines.begin_delete(resource_group, vm_name).result()
        logging.info(f"Deleted VM '{vm_name}'.")
    except Exception as e:
        logging.info(f"Could not delete VM '{vm_name}': {e}")
        os_disk_name = None

    # Delete OS disk if available
    if os_disk_name:
        try:
            compute_client.disks.begin_delete(resource_group, os_disk_name).result()
            logging.info(f"Deleted OS disk '{os_disk_name}'.")
        except Exception as e:
            logging.info(f"Could not delete OS disk '{os_disk_name}': {e}")

    # Delete NIC
    try:
        network_client.network_interfaces.begin_delete(resource_group, f"{vm_name}-nic").result()
        logging.info(f"Deleted NIC '{vm_name}-nic'.")
    except Exception as e:
        logging.info(f"Could not delete NIC '{vm_name}-nic': {e}")

    # Delete NSG
    try:
        network_client.network_security_groups.begin_delete(resource_group, f"{vm_name}-nsg").result()
        logging.info(f"Deleted NSG '{vm_name}-nsg'.")
    except Exception as e:
        logging.info(f"Could not delete NSG '{vm_name}-nsg': {e}")

    # Delete Public IP
    try:
        network_client.public_ip_addresses.begin_delete(resource_group, f"{vm_name}-public-ip").result()
        logging.info(f"Deleted Public IP '{vm_name}-public-ip'.")
    except Exception as e:
        logging.info(f"Could not delete Public IP '{vm_name}-public-ip': {e}")

    # Delete VNet
    try:
        network_client.virtual_networks.begin_delete(resource_group, f"{vm_name}-vnet").result()
        logging.info(f"Deleted VNet '{vm_name}-vnet'.")
    except Exception as e:
        logging.info(f"Could not delete VNet '{vm_name}-vnet': {e}")

    # Delete Storage Account
    try:
        logging.info(f"Deleting blob '{blob_name}' from container '{container_name}'.")
        container_client = blob_service_client.get_container_client(container_name)
        container_client.delete_blob(blob_name)
        logging.info(f"Deleted blob '{blob_name}' from container '{container_name}'.")
        logging.info(f"Deleting container '{container_name}'.")
        blob_service_client.delete_container(container_name)
        logging.info(f"Deleted container '{container_name}'.")
        logging.info(f"Deleting storage account '{storage_account_name}'.")
        storage_client.storage_accounts.delete(resource_group, storage_account_name)
        logging.info(f"Deleted storage account '{storage_account_name}'.")
    except Exception as e:
        logging.info(f"Could not delete Storage Account '{storage_account_name}': {e}")

    # Delete DNS A record (keep DNS zone)
    for record_name in a_records:
        record_to_delete = record_name if record_name else '@'  # handle root domain with '@'
        try:
            dns_client.record_sets.delete(resource_group, domain, record_to_delete, 'A')
            logging.info(f"Deleted DNS A record '{record_to_delete}' in zone '{domain}'.")
        except Exception as e:
            logging.info(f"Could not delete DNS A record '{record_to_delete}' in zone '{domain}': {e}")

    logging.info("Cleanup completed.")
