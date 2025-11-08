from django.db import transaction
from django.db.models import Q
from functools import lru_cache
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
import re

from nautobot.dcim.models import Device, Interface
from nautobot.apps.choices import InterfaceTypeChoices
from nautobot.ipam.models import Prefix, IPAddress, VRF
from nautobot.extras.models import Status, Role
from nautobot.apps.jobs import Job, ObjectVar, StringVar, ChoiceVar

from .utils import hl
from . import constants

name = "SC25 Routing Jobs"  # Grouping shown in the UI


class CreateLoopbackInterface(Job):
    """
    Create a new virtual loopback interface for a device with the following capabilities:
    - Create a new virtual interface with specified name
    - Set appropriate role, status, and VRF
    - Allocate IP addresses from loopback prefixes (role="Loopback", type="Network")
    - Set DNS names following naming convention
    """

    # Input variables
    device = ObjectVar(
        description="Device to create loopback interface for",
        required=True,
        model=Device,
        display_field="name",
    )

    interface_name = StringVar(
        description="Interface name for the new loopback interface",
        required=True,
    )

    vrf = ObjectVar(
        description="VRF for the loopback interface",
        required=True,
        model=VRF,
        display_field="name",
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

    class Meta:
        name = "Create Loopback Interface"
        description = "Create a new virtual loopback interface for a device including IP allocation"
        has_sensitive_variables = False

    @property
    @lru_cache(maxsize=1)
    def active_status(self):
        return Status.objects.get(name=constants.ACTIVE_STATUS)

    @property
    @lru_cache(maxsize=1)
    def loopback_role(self):
        return Role.objects.get(name="Loopback")

    def _get_loopback_prefix_queryset(self, vrf, ip_version):
        """Get the queryset for loopback prefixes matching the specified criteria."""
        return Prefix.objects.filter(
            vrfs=vrf,
            ip_version=ip_version,
            role__name="Loopback",
            type="network"
        ).exclude(
            status__name="Deprecated"
        ).order_by("prefix_length")

    def _perform_sanity_checks(self, device, interface_name, vrf, ip_version):
        """Perform sanity checks before proceeding."""
        # Check 1: VRF is assigned to the specified Device
        if vrf not in device.vrfs.all():
            raise RuntimeError(f"VRF '{vrf.name}' is not assigned to device '{device.name}'")
        
        self.logger.info(f"✅ VRF '{vrf.name}' is assigned to device '{device.name}'")

        # Check 2: VRF has loopback prefixes available for the specified IP version(s)
        if ip_version in ["ipv4", "both"]:
            v4_prefixes = self._get_loopback_prefix_queryset(vrf, 4)
            if not v4_prefixes.exists():
                raise RuntimeError(f"VRF '{vrf.name}' has no suitable IPv4 loopback prefixes (role='Loopback', type='Network')")
        
        if ip_version in ["ipv6", "both"]:
            v6_prefixes = self._get_loopback_prefix_queryset(vrf, 6)
            if not v6_prefixes.exists():
                raise RuntimeError(f"VRF '{vrf.name}' has no suitable IPv6 loopback prefixes (role='Loopback', type='Network')")

        # Check 3: Device doesn't already have an interface with the provided name
        existing_interface = Interface.objects.filter(
            device=device,
            name=interface_name
        ).first()

        if existing_interface:
            raise RuntimeError(f"Interface '{interface_name}' already exists on device '{device.name}'")

        self.logger.info("✅ All sanity checks passed")

    def _find_loopback_prefixes(self, vrf, ip_version):
        """Find loopback prefixes for IP allocation."""
        prefixes = {}

        if ip_version in ["ipv4", "both"]:
            v4_prefixes = self._get_loopback_prefix_queryset(vrf, 4)
            
            if not v4_prefixes.exists():
                raise RuntimeError(f"No suitable IPv4 loopback prefixes found in VRF '{vrf.name}'")
            
            prefixes['v4'] = v4_prefixes.first()
            self.logger.info(f"📋 Found IPv4 loopback prefix: {hl(prefixes['v4'])}")

        if ip_version in ["ipv6", "both"]:
            v6_prefixes = self._get_loopback_prefix_queryset(vrf, 6)

            if not v6_prefixes.exists():
                raise RuntimeError(f"No suitable IPv6 loopback prefixes found in VRF '{vrf.name}'")
            
            prefixes['v6'] = v6_prefixes.first()
            self.logger.info(f"📋 Found IPv6 loopback prefix: {hl(prefixes['v6'])}")

        return prefixes

    def _clean_interface_name(self, interface_name):
        """Clean interface name for DNS usage."""
        # Replace any character that isn't A-Z, a-z, or 0-9 with an underscore, and make it all lowercase
        return re.sub(r'[^A-Za-z0-9]', '_', interface_name).lower()

    def _generate_dns_name(self, device, interface_name, vrf):
        """Generate DNS name for the interface."""
        clean_name = self._clean_interface_name(interface_name)
        # Format: (clean interface name).(device name).(vrf name).net.25.scconf.org
        dns_name = f"{clean_name}.{device.name}.{vrf.name}.{constants.LOOPBACK_DNS_DOMAIN}"
        return dns_name

    def _allocate_ipv4_address(self, prefix, interface_name, device, vrf):
        """Allocate an IPv4 address from the loopback prefix."""
        # Use Nautobot's native IPAM to get next available IP
        next_ip = prefix.get_first_available_ip()
        
        if not next_ip:
            raise RuntimeError(f"No available IPv4 addresses in prefix {prefix.prefix}")

        # Create IP address as /32
        ip_str = str(next_ip).split('/')[0] + "/32"
        
        ip_address = IPAddress.objects.create(
            address=ip_str,
            ip_version=4,
            type="host",
            status=self.active_status,
            role=self.loopback_role,
            dns_name=self._generate_dns_name(device, interface_name, vrf),
            description=f"{device.name} {interface_name}",
        )

        self.logger.info(f"✅ Allocated IPv4 address: {hl(ip_address)}")
        return ip_address

    def _derive_ipv6_from_ipv4(self, ipv4_address, v6_prefix):
        """Derive IPv6 address from IPv4 address using same host bits."""
        # Get host bits from IPv4
        ipv4_obj = ip_address(ipv4_address.address.ip)
        last_octet = str(ipv4_obj).split('.')[-1]

        # Get the base IPv6 network
        ipv6_network = ip_network(v6_prefix.prefix)
        
        # Return as string with /128
        ipv6_str = f"{str(ipv6_network.network_address)}{last_octet}/128"
        return ipv6_str

    def _allocate_ipv6_address(self, prefix, interface_name, device, vrf, existing_ipv4=None):
        """Allocate an IPv6 address from the loopback prefix."""
        # If we have an existing IPv4 address, derive IPv6 from it
        if existing_ipv4:
            ipv6_str = self._derive_ipv6_from_ipv4(existing_ipv4, prefix)
            self.logger.info(f"📐 Derived IPv6 address from IPv4: {ipv6_str}")
        else:
            # Use Nautobot's native IPAM to get next available IP
            next_ip = prefix.get_first_available_ip()
            
            if not next_ip:
                raise RuntimeError(f"No available IPv6 addresses in prefix {prefix.prefix}")

            # Create IP address as /128
            ipv6_str = str(next_ip).split('/')[0] + "/128"

        # Check if this IP is already in use
        existing_ip = IPAddress.objects.filter(address=ipv6_str).first()
        if existing_ip:
            if existing_ipv4:
                raise RuntimeError(f"Derived IPv6 address {ipv6_str} is already in use. Cannot proceed with dual-stack allocation.")
            else:
                # For IPv6-only, get the next available
                next_ip = prefix.available_ips.exclude(address__in=[existing_ip.address]).first()
                if not next_ip:
                    raise RuntimeError(f"No available IPv6 addresses in prefix {prefix.prefix}")
                ipv6_str = str(next_ip) + "/128"

        ip_address_obj = IPAddress.objects.create(
            address=ipv6_str,
            ip_version=6,
            type="host",
            status=self.active_status,
            role=self.loopback_role,
            dns_name=self._generate_dns_name(device, interface_name, vrf),
            description=f"{device.name} {interface_name}"
        )

        self.logger.info(f"✅ Allocated IPv6 address: {hl(ip_address_obj)}")
        return ip_address_obj

    def _create_loopback_interface(self, device, interface_name, vrf):
        """Create a new virtual loopback interface."""
        interface = Interface.objects.create(
            device=device,
            name=interface_name,
            type=InterfaceTypeChoices.TYPE_VIRTUAL,
            status=self.active_status,
            role=self.loopback_role,
            vrf=vrf,
            description=f"{vrf.name} VRF Loopback",
        )

        self.logger.info(f"➕ Created loopback interface: {hl(interface)}")
        return interface

    @transaction.atomic
    def run(self, device, interface_name, vrf, ip_version):
        """Main execution method."""
        self.logger.info(f"🚀 Starting loopback interface creation for device: {hl(device)}")

        # Step 1: Perform sanity checks
        self._perform_sanity_checks(device, interface_name, vrf, ip_version)

        # Step 2: Find loopback prefixes
        prefixes = self._find_loopback_prefixes(vrf, ip_version)

        # Step 3: Allocate IP addresses
        ipv4_address = None
        ipv6_address = None

        # Allocate IPv4 if needed
        if ip_version in ["ipv4", "both"]:
            ipv4_address = self._allocate_ipv4_address(
                prefixes['v4'],
                interface_name,
                device,
                vrf
            )

        # Allocate IPv6 if needed
        if ip_version in ["ipv6", "both"]:
            ipv6_address = self._allocate_ipv6_address(
                prefixes['v6'],
                interface_name,
                device,
                vrf,
                existing_ipv4=ipv4_address if ip_version == "both" else None
            )

        # Step 4: Create loopback interface
        interface = self._create_loopback_interface(device, interface_name, vrf)

        # Step 5: Attach IP addresses to interface
        if ipv4_address:
            interface.ip_addresses.add(ipv4_address)
            self.logger.info(f"➕ Attached IPv4 {hl(ipv4_address)} to interface {hl(interface)}")

        if ipv6_address:
            interface.ip_addresses.add(ipv6_address)
            self.logger.info(f"➕ Attached IPv6 {hl(ipv6_address)} to interface {hl(interface)}")

        # Summary
        dns_name = self._generate_dns_name(device, interface_name, vrf)
        self.logger.info(f"""
        ✅ Loopback interface creation completed for {hl(device)}:

        Interface: {hl(interface)}
        VRF: {hl(vrf)}
        IPv4: {hl(ipv4_address) if ipv4_address else 'Not allocated'}
        IPv6: {hl(ipv6_address) if ipv6_address else 'Not allocated'}
        DNS Name: {dns_name}
        """)

