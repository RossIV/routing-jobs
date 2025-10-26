from django.db import transaction
from django.db.models import Q
from functools import lru_cache

from nautobot.dcim.models import Device, Interface
from nautobot.apps.choices import InterfaceTypeChoices
from nautobot.ipam.models import Prefix, IPAddress, VLAN
from nautobot.extras.models import Status, Role
from nautobot.tenancy.models import Tenant
from nautobot.apps.jobs import Job, ObjectVar, StringVar, ChoiceVar, BooleanVar

from utils import hl
import constants

name = "SC25 Routing Jobs"  # Grouping shown in the UI

class CreateManagementInterface(Job):
    """
    Create a new virtual management interface for a device with the following capabilities:
    - Create a new virtual interface with a generated name
    - Set appropriate role, status, and management settings
    - Allocate IP addresses from VLAN prefixes (VLANs must be Active and have Tenant Group "SCinet")
    - Set DNS names and primary IP addresses on the device
    """

    # Input variables
    device = ObjectVar(
        description="Device to create management interface for",
        required=True,
        model=Device,
        display_field="name",
    )

    interface_name = StringVar(
        description="Interface name for the new virtual interface",
        required=True,
    )

    vlan = ObjectVar(
        description="VLAN which the management interface will be connected to",
        required=True,
        model=VLAN,
        display_field="name",
        query_params={
            "status": "Active",
            "tenant__tenant_group__name": "SCinet"
        },
    )

    ip_version = ChoiceVar(
        choices=[
            ("ipv4", "IPv4 only"),
            ("ipv6", "IPv6 only"),
            ("both", "Both IPv4 and IPv6"),
        ],
        description="IP version(s) to allocate",
        required=True,
        default="both",
    )

    prefix_dns_name = BooleanVar(
        description="Prefix DNS name with 'mgmt-' (if unchecked, uses device name only)",
        required=False,
        default=True,
    )

    class Meta:
        name = "Create New Management Interface"
        description = "Create a new (virtual) management interface for a device including IP allocation"
        has_sensitive_variables = False

    @property
    @lru_cache(maxsize=1)
    def planned_status(self):
        return Status.objects.get(name=constants.PLANNED_STATUS)

    @property
    @lru_cache(maxsize=1)
    def active_status(self):
        return Status.objects.get(name=constants.ACTIVE_STATUS)

    @property
    @lru_cache(maxsize=1)
    def management_role(self):
        return Role.objects.get(name="Management")

    def _create_virtual_interface(self, device, interface_name, vlan):
        """Create a new virtual interface for management."""
        # Check if interface already exists
        existing_interface = Interface.objects.filter(
            device=device,
            name=interface_name
        ).first()

        if existing_interface:
            raise RuntimeError(f"Interface '{interface_name}' already exists on device '{device.name}'")

        # Create new virtual interface
        interface = Interface.objects.create(
            device=device,
            name=interface_name,
            type=InterfaceTypeChoices.TYPE_VIRTUAL,
            status=self.planned_status,
            role=self.management_role,
            mgmt_only=True,
            description=f"Management interface for {device.name}",
            untagged_vlan=vlan,
        )

        self.logger.info(f"➕ Created new virtual interface: {hl(interface)}")
        return interface

    def _find_management_prefixes(self, vlan, ip_version):
        """Find prefixes associated with the VLAN that can be used for management IP allocation."""
        prefixes = []

        if ip_version in ["ipv4", "both"]:
            v4_prefixes = Prefix.objects.filter(
                vlan=vlan,
                ip_version=4,
                type__in=["network", "pool"]
            ).exclude(
                status__name="Deprecated"
            ).order_by("prefix_length")
            prefixes.extend(v4_prefixes)

        if ip_version in ["ipv6", "both"]:
            v6_prefixes = Prefix.objects.filter(
                vlan=vlan,
                ip_version=6,
                type__in=["network", "pool"]
            ).exclude(
                status__name="Deprecated"
            ).order_by("prefix_length")
            prefixes.extend(v6_prefixes)

        if not prefixes:
            raise RuntimeError(f"No suitable prefixes found in VLAN {vlan.name} for IP version {ip_version}")

        return prefixes

    def _configure_ip_address(self, ip_address, interface, device, prefix_dns_name=True):
        """Configure IP address with management settings and assign to interface."""
        if prefix_dns_name:
            dns_name = f"mgmt-{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"
        else:
            dns_name = f"{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"

        # Update IP address with management settings
        ip_address.status = self.active_status
        ip_address.description = f"Management IP for {device.name}"
        ip_address.dns_name = dns_name
        ip_address.save()

        self.logger.info(f"✅ Configured IP address: {hl(ip_address)}")

        # Assign to interface if not already assigned
        if not interface.ip_addresses.filter(pk=ip_address.pk).exists():
            interface.ip_addresses.add(ip_address)
            self.logger.info(f"➕ Assigned IP {hl(ip_address)} to interface {hl(interface)}")

        return ip_address

    def _set_primary_ips(self, device, ipv4_address, ipv6_address):
        """Set primary IPv4 and IPv6 addresses on the device."""
        if ipv4_address:
            device.primary_ip4 = ipv4_address
            self.logger.info(f"✅ Set primary IPv4: {hl(ipv4_address)}")

        if ipv6_address:
            device.primary_ip6 = ipv6_address
            self.logger.info(f"✅ Set primary IPv6: {hl(ipv6_address)}")

        device.save()

    @transaction.atomic
    def run(self, device, interface_name, vlan, ip_version, prefix_dns_name):
        """Main execution method."""
        self.logger.info(f"🚀 Starting management interface creation for device: {hl(device)}")

        # Step 1: Create new virtual interface
        interface = self._create_virtual_interface(device, interface_name, vlan)

        # Step 2: Find management prefixes
        prefixes = self._find_management_prefixes(vlan, ip_version)
        self.logger.info(f"📋 Found {len(prefixes)} suitable prefix(es) in VLAN {hl(vlan)}")

        # Step 3: Allocate IP addresses
        ipv4_address = None
        ipv6_address = None

        for prefix in prefixes:
            try:
                # Use Nautobot's native IPAM to get next available IP
                next_ip_address = prefix.available_ips.create()
                ip_address = self._configure_ip_address(next_ip_address, interface, device, prefix_dns_name)

                if prefix.ip_version == 4:
                    ipv4_address = ip_address
                elif prefix.ip_version == 6:
                    ipv6_address = ip_address

            except Exception as e:
                self.logger.error(f"❌ Failed to allocate IP from prefix {hl(prefix)}: {str(e)}")
                continue

        # Step 4: Set primary IPs on device
        if ipv4_address or ipv6_address:
            self._set_primary_ips(device, ipv4_address, ipv6_address)

        # Summary
        dns_name = f"mgmt-{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}" if prefix_dns_name else f"{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"
        self.logger.info(f"""
        ✅ Management interface creation completed for {hl(device)}:

        Interface: {hl(interface)}
        VLAN: {hl(vlan)}
        IPv4: {hl(ipv4_address) if ipv4_address else 'Not allocated'}
        IPv6: {hl(ipv6_address) if ipv6_address else 'Not allocated'}
        DNS Name: {dns_name}
        """)


class ConfigureExistingInterfaceForManagement(Job):
    """
    Configure an existing interface for management with the following capabilities:
    - Configure an existing interface with management settings
    - Set appropriate role, status, and management settings
    - Allocate IP addresses from VLAN prefixes (VLANs must be Active and have Tenant Group "SCinet")
    - Set DNS names and primary IP addresses on the device
    """

    # Input variables
    device = ObjectVar(
        description="Device containing the interface to configure",
        required=True,
        model=Device,
        display_field="name",
    )

    interface = ObjectVar(
        description="Existing interface to configure for management",
        required=True,
        model=Interface,
        display_field="name",
        query_params={"device_id": "$device"},
    )

    vlan = ObjectVar(
        description="VLAN to connect the management interface to",
        required=True,
        model=VLAN,
        display_field="name",
        query_params={
            "status": "Active",
            "tenant__tenant_group__name": "SCinet"
        },
    )

    ip_version = ChoiceVar(
        choices=[
            ("ipv4", "IPv4 only"),
            ("ipv6", "IPv6 only"),
            ("both", "Both IPv4 and IPv6"),
        ],
        description="IP version(s) to allocate",
        required=True,
        default="both",
    )

    prefix_dns_name = BooleanVar(
        description="Prefix DNS name with 'mgmt-' (if unchecked, uses device name only)",
        required=False,
        default=True,
    )

    class Meta:
        name = "Configure Existing Interface for Management"
        description = "Configure an existing interface for management with IP allocation"
        has_sensitive_variables = False

    @property
    @lru_cache(maxsize=1)
    def planned_status(self):
        return Status.objects.get(name=constants.PLANNED_STATUS)

    @property
    @lru_cache(maxsize=1)
    def active_status(self):
        return Status.objects.get(name=constants.ACTIVE_STATUS)

    @property
    @lru_cache(maxsize=1)
    def management_role(self):
        return Role.objects.get(name="Management")

    def _configure_existing_interface(self, interface, vlan):
        """Configure an existing interface for management."""
        # Update interface with management settings
        interface.status = self.planned_status
        interface.role = self.management_role
        interface.mgmt_only = True
        interface.description = f"Management interface for {interface.device.name}"
        interface.untagged_vlan = vlan
        interface.save()

        self.logger.info(f"✅ Configured existing interface for management: {hl(interface)}")
        return interface

    def _find_management_prefixes(self, vlan, ip_version):
        """Find prefixes associated with the VLAN that can be used for management IP allocation."""
        prefixes = []

        if ip_version in ["ipv4", "both"]:
            v4_prefixes = Prefix.objects.filter(
                vlan=vlan,
                ip_version=4,
                type__in=["network"]
            ).exclude(
                status__name="Deprecated"
            ).order_by("prefix_length")
            prefixes.extend(v4_prefixes)

        if ip_version in ["ipv6", "both"]:
            v6_prefixes = Prefix.objects.filter(
                vlan=vlan,
                ip_version=6,
                type__in=["network"]
            ).exclude(
                status__name="Deprecated"
            ).order_by("prefix_length")
            prefixes.extend(v6_prefixes)

        if not prefixes:
            raise RuntimeError(f"No suitable prefixes found in VLAN {vlan.name} for IP version {ip_version}")

        return prefixes

    def _configure_ip_address(self, ip_address, interface, device, prefix_dns_name=True):
        """Configure IP address with management settings and assign to interface."""
        if prefix_dns_name:
            dns_name = f"mgmt-{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"
        else:
            dns_name = f"{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"

        # Update IP address with management settings
        ip_address.status = self.active_status
        ip_address.description = f"Management IP for {device.name}"
        ip_address.dns_name = dns_name
        ip_address.save()

        self.logger.info(f"✅ Configured IP address: {hl(ip_address)}")

        # Assign to interface if not already assigned
        if not interface.ip_addresses.filter(pk=ip_address.pk).exists():
            interface.ip_addresses.add(ip_address)
            self.logger.info(f"➕ Assigned IP {hl(ip_address)} to interface {hl(interface)}")

        return ip_address

    def _set_primary_ips(self, device, ipv4_address, ipv6_address):
        """Set primary IPv4 and IPv6 addresses on the device."""
        if ipv4_address:
            device.primary_ip4 = ipv4_address
            self.logger.info(f"✅ Set primary IPv4: {hl(ipv4_address)}")

        if ipv6_address:
            device.primary_ip6 = ipv6_address
            self.logger.info(f"✅ Set primary IPv6: {hl(ipv6_address)}")

        device.save()

    @transaction.atomic
    def run(self, device, interface, vlan, ip_version, prefix_dns_name):
        """Main execution method."""
        self.logger.info(f"🚀 Starting management interface configuration for device: {hl(device)}")

        # Step 1: Configure existing interface
        configured_interface = self._configure_existing_interface(interface, vlan)

        # Step 2: Find management prefixes
        prefixes = self._find_management_prefixes(vlan, ip_version)
        self.logger.info(f"📋 Found {len(prefixes)} suitable prefix(es) in VLAN {hl(vlan)}")

        # Step 3: Allocate IP addresses
        ipv4_address = None
        ipv6_address = None

        for prefix in prefixes:
            try:
                next_ip = self._get_next_available_ip(prefix)
                ip_address = self._create_ip_address(next_ip, configured_interface, device, vlan)

                if prefix.ip_version == 4:
                    ipv4_address = ip_address
                elif prefix.ip_version == 6:
                    ipv6_address = ip_address

            except Exception as e:
                self.logger.error(f"❌ Failed to allocate IP from prefix {hl(prefix)}: {str(e)}")
                continue

        # Step 4: Set primary IPs on device
        if ipv4_address or ipv6_address:
            self._set_primary_ips(device, ipv4_address, ipv6_address)

        # Summary
        dns_name = f"mgmt-{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}" if prefix_dns_name else f"{device.name}.{constants.MANAGEMENT_DNS_DOMAIN}"
        self.logger.info(f"""
        ✅ Management interface configuration completed for {hl(device)}:

        Interface: {hl(configured_interface)}
        VLAN: {hl(vlan)}
        IPv4: {hl(ipv4_address) if ipv4_address else 'Not allocated'}
        IPv6: {hl(ipv6_address) if ipv6_address else 'Not allocated'}
        DNS Name: {dns_name}
        """)