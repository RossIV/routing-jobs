from django.db import transaction
from django.db.models import Q
from functools import lru_cache
import re

from nautobot.dcim.models import Device, Interface, Location
from nautobot.circuits.models import Circuit, Provider, CircuitTermination, CircuitType
from nautobot.ipam.models import Prefix, IPAddress, VRF
from nautobot.extras.models import Status, Role, Relationship, RelationshipAssociation
from nautobot.tenancy.models import Tenant
from nautobot.apps.jobs import Job, ObjectVar, StringVar, ChoiceVar, BooleanVar
from ipaddress import ip_network
from django.contrib.contenttypes.models import ContentType

from .utils import hl
from . import constants

name = "SC25 Routing Jobs"  # Grouping shown in the UI


class CreateExhibitorConnection(Job):
    """
    Create a complete exhibitor connection including circuit, prefix allocation,
    IP address assignment, and interface configuration.
    """

    # Input variables
    location = ObjectVar(
        description="Location (Booth) for the connection",
        required=True,
        model=Location,
        display_field="name",
        query_params={
            "tenant__isnull": False,
        },
    )

    connection_identifier = ChoiceVar(
        choices=[(chr(i), chr(i)) for i in range(ord('A'), ord('Z') + 1)],
        required=True,
    )

    ipv4_enabled = BooleanVar(
        label="Enable IPv4",
        description="Allocates an IPv4 subnet for the connection",
        required=True,
        default=True,
    )

    ipv6_enabled = BooleanVar(
        label="Enable IPv6",
        description="Allocates an IPv6 subnet for the connection",
        required=True,
        default=True,
    )

    subnet_size_ipv4 = ChoiceVar(
        choices=[
            ("31", "/31"),
            ("30", "/30"),
            ("29", "/29"),
            ("28", "/28"),
            ("27", "/27"),
            ("26", "/26"),
            ("25", "/25"),
            ("24", "/24"),
        ],
        description="Size of IPv4 subnet to allocate",
        label="Subnet Size (IPv4)",
        required=True,
        default="27",
    )

    device = ObjectVar(
        description="Device to connect to",
        required=True,
        model=Device,
        display_field="name",
        query_params={
            "role__name__in": ["DNOC Switch", "NOC Router", "SCN Router"]
        },
    )

    speed = ChoiceVar(
        choices=[
            (1000000, "1 Gbps"),
            (10000000, "10 Gbps"),
            (100000000, "100 Gbps"),
            (400000000, "400 Gbps"),
        ],
        description="Connection speed",
        required=True,
    )

    connection_type = ChoiceVar(
        choices=[
            ("Exhibitor", "Exhibitor"),
            ("NRE", "NRE"),
        ],
        description="Connection type",
        required=True,
    )

    firewalled = BooleanVar(
        description="Firewalled connection",
        required=True,
        default=True,
    )

    class Meta:
        name = "Create Exhibitor Connection"
        description = "Create a complete exhibitor connection with circuit, prefix, IP, and interface configuration"
        has_sensitive_variables = False

    @property
    @lru_cache(maxsize=1)
    def active_status(self):
        return Status.objects.get(name=constants.ACTIVE_STATUS)

    @property
    @lru_cache(maxsize=1)
    def planned_status(self):
        return Status.objects.get(name=constants.PLANNED_STATUS)

    @property
    @lru_cache(maxsize=1)
    def scinet_provider(self):
        return Provider.objects.get(name="SCinet")

    @property
    @lru_cache(maxsize=1)
    def exhibitor_role(self):
        return Role.objects.get(name="Exhibitor Connection")

    @property
    @lru_cache(maxsize=1)
    def exhibitor_connection_role(self):
        return Role.objects.get(name="Exhibitor Connection (L3)")

    def _extract_booth_number(self, location_name):
        """Extract booth number from location name using regex."""
        match = re.search(r'(\d+)', location_name)
        if not match:
            raise RuntimeError(f"Could not extract booth number from location name: {location_name}")
        return match.group(1)

    def _generate_circuit_name(self, booth_number, connection_identifier):
        """Generate circuit name from booth number and connection identifier."""
        return f"{booth_number}-{connection_identifier}"

    def _check_duplicate_circuit(self, circuit_name):
        """Check if a circuit with the same name already exists."""
        existing_circuit = Circuit.objects.filter(cid=circuit_name).first()
        if existing_circuit:
            raise RuntimeError(f"Circuit with CID '{circuit_name}' already exists: {hl(existing_circuit)}")

    def _get_dnoc_location(self, location):
        """Get DNOC location from custom relationship."""
        try:
            # Access the custom relationship using Nautobot's relationship API
            relationship = Relationship.objects.get(key='booth_to_dnoc')
            
            # Get the relationship association
            relationships = location.get_relationships()
            for rel_key, rel_data in relationships.items():
                if rel_key == 'booth_to_dnoc':
                    # Return the destination (many side)
                    destinations = rel_data.get('destinations', [])
                    if destinations:
                        return destinations[0]
            
            raise RuntimeError(f"No DNOC location found via relationship 'booth_to_dnoc' for {hl(location)}")
        except Exception as e:
            raise RuntimeError(f"Could not find DNOC location for {hl(location)}: {str(e)}")

    def _create_circuit(self, location, connection_identifier, speed):
        """Create a circuit for the exhibitor connection."""
        booth_number = self._extract_booth_number(location.name)
        circuit_name = self._generate_circuit_name(booth_number, connection_identifier)

        # Check for duplicates
        self._check_duplicate_circuit(circuit_name)

        # Get DNOC location
        dnoc_location = self._get_dnoc_location(location)

        # Create circuit
        circuit = Circuit.objects.create(
            cid=circuit_name,
            provider=self.scinet_provider,
            type=None,  # Set if needed
            status=self.planned_status,
            tenant=location.tenant,
            role=self.exhibitor_role,
            commit_rate=speed,
            description=f"Exhibitor connection for {location.name}",
        )

        self.logger.info(f"➕ Created circuit: {hl(circuit)}")

        # Create terminations
        # A Side: DNOC location
        CircuitTermination.objects.create(
            circuit=circuit,
            term_side='A',
            location=dnoc_location,
        )

        # Z Side: Booth location
        CircuitTermination.objects.create(
            circuit=circuit,
            term_side='Z',
            location=location,
        )

        self.logger.info(f"➕ Created circuit terminations: A-side={hl(dnoc_location)}, Z-side={hl(location)}")

        return circuit

    def _find_container_prefix(self, ip_version, connection_type):
        """Find container prefix for allocation."""
        type_filter = "Container"
        role_filter = "Exhibitor Connection (L3)"

        prefixes = Prefix.objects.filter(
            ip_version=ip_version,
            type=type_filter,
            role__name=role_filter,
            namespace__name="Global"
        ).exclude(
            status__name="Deprecated"
        )

        if not prefixes.exists():
            raise RuntimeError(f"No container prefixes found for IPv{ip_version} with role '{role_filter}' in Global namespace")

        return prefixes.first()

    def _find_next_available_subnet(self, container_prefix, prefix_length):
        """Find the next available subnet of the specified length within the container."""
        container_network = ip_network(str(container_prefix.prefix))
        
        # Get all existing subnets within this container
        existing_subnets = Prefix.objects.filter(
            prefix__net_contained_or_equal=str(container_prefix.prefix),
            prefix_length=prefix_length
        ).exclude(
            status__name="Deprecated"
        )

        existing_ranges = set()
        for subnet in existing_subnets:
            existing_ranges.add(ip_network(str(subnet.prefix)))

        # Find the first available subnet
        subnet_gen = container_network.subnets(new_prefix=prefix_length)
        for subnet in subnet_gen:
            if subnet not in existing_ranges:
                return subnet
        
        raise RuntimeError(f"No available /{prefix_length} subnet in container {container_prefix.prefix}")

    def _allocate_prefix(self, circuit, location, ip_version, prefix_length, connection_type, firewalled):
        """Allocate a new prefix for the circuit."""
        # Only allocate if connection type is Exhibitor
        if connection_type != "Exhibitor":
            return None

        # Find container prefix
        container_prefix = self._find_container_prefix(ip_version, connection_type)
        
        # Find next available subnet
        available_subnet = self._find_next_available_subnet(container_prefix, prefix_length)
        
        # Create new prefix
        # Get namespace from container
        namespace = container_prefix.namespace
        
        # Create prefix object
        prefix = Prefix(
            prefix=str(available_subnet),
            ip_version=ip_version,
            status=self.active_status,
            role=self.exhibitor_connection_role,
            description=circuit.cid,
            tenant=location.tenant,
            namespace=namespace,
        )
        prefix.type = "Network"
        prefix.save()

        # Assign to VRF based on firewalled status
        vrf_name = "exhibitor" if firewalled else "dmz"
        try:
            vrf = VRF.objects.get(name=vrf_name)
            prefix.vrf = vrf
            prefix.save()
        except VRF.DoesNotExist:
            self.logger.warning(f"VRF '{vrf_name}' not found, skipping VRF assignment")

        # Associate prefix with circuit via custom relationship
        try:
            relationship = Relationship.objects.get(key='prefix')
            source_type = ContentType.objects.get_for_model(Circuit)
            destination_type = ContentType.objects.get_for_model(Prefix)
            RelationshipAssociation.objects.create(
                relationship=relationship,
                source_id=circuit.pk,
                source_type=source_type,
                destination_id=prefix.pk,
                destination_type=destination_type,
            )
            self.logger.info(f"➕ Related prefix {hl(prefix)} to circuit via relationship")
        except Exception as e:
            self.logger.warning(f"Could not relate prefix to circuit: {str(e)}")

        self.logger.info(f"➕ Allocated prefix: {hl(prefix)}")
        return prefix

    def _create_ip_address_from_prefix(self, prefix, circuit_name, location):
        """Create an IP address from the prefix (first host or ::1 for IPv6)."""
        prefix_network = ip_network(str(prefix.prefix))
        
        if prefix.ip_version == 6:
            # Use ::1 for IPv6
            ip_address_str = f"{prefix_network.network_address + 1}/{prefix.prefix_length}"
        else:
            # Use first host for IPv4
            ip_address_str = f"{prefix_network.network_address + 1}/{prefix.prefix_length}"
        
        # Get VRF
        vrf = prefix.vrf if prefix.vrf else None

        # Create IP address
        ip_address = IPAddress.objects.create(
            address=ip_address_str,
            ip_version=prefix.ip_version,
            status=self.active_status,
            description=circuit_name,
            dns_name=None,  # Will be set below
            tenant=location.tenant,
            vrf=vrf,
        )

        # Set DNS name
        booth_number = self._extract_booth_number(location.name)
        # Extract connection identifier from circuit name
        conn_id = circuit_name.split('-')[1] if '-' in circuit_name else 'A'
        dns_name = f"{conn_id}01.{booth_number}.{constants.MANAGEMENT_DNS_DOMAIN}"
        ip_address.dns_name = dns_name
        ip_address.save()

        self.logger.info(f"➕ Created IP address: {hl(ip_address)}")
        return ip_address

    def _find_next_available_interface(self, device):
        """Find the next available interface with role 'Exhibitor Connection (L3)'."""
        interfaces = Interface.objects.filter(
            device=device,
            role__name="Exhibitor Connection (L3)",
            ip_addresses__isnull=True
        ).order_by('name')

        if not interfaces.exists():
            raise RuntimeError(f"No available interfaces with role 'Exhibitor Connection (L3)' on {hl(device)}")

        return interfaces.first()

    def _configure_interface(self, interface, ip_addresses, circuit_name, location):
        """Configure interface with IP addresses and description."""
        # Get VRF from first IP address
        vrf = ip_addresses[0].vrf if ip_addresses and ip_addresses[0].vrf else None
        
        # Set description
        interface.description = f"{circuit_name}: {location.tenant.name if location.tenant else 'Unknown'}"
        interface.vrf = vrf
        interface.save()

        # Assign IP addresses
        for ip_address in ip_addresses:
            interface.ip_addresses.add(ip_address)
            self.logger.info(f"➕ Assigned IP {hl(ip_address)} to interface {hl(interface)}")

        self.logger.info(f"✅ Configured interface: {hl(interface)}")
        return interface

    @transaction.atomic
    def run(self, location, connection_identifier, ipv4_enabled, ipv6_enabled, 
            subnet_size_ipv4, device, speed, connection_type, firewalled):
        """Main execution method."""
        self.logger.info(f"🚀 Starting exhibitor connection creation for location: {hl(location)}")

        # Step 1: Create circuit
        circuit = self._create_circuit(location, connection_identifier, speed)
        
        # Step 2: Allocate prefixes
        prefixes = []
        if ipv4_enabled and connection_type == "Exhibitor":
            prefix_ipv4 = self._allocate_prefix(circuit, location, 4, int(subnet_size_ipv4), connection_type, firewalled)
            if prefix_ipv4:
                prefixes.append(prefix_ipv4)
        
        if ipv6_enabled and connection_type == "Exhibitor":
            # Default IPv6 prefix length (typically /64 for LANs)
            prefix_ipv6 = self._allocate_prefix(circuit, location, 6, 64, connection_type, firewalled)
            if prefix_ipv6:
                prefixes.append(prefix_ipv6)

        # Step 3: Create IP addresses
        ip_addresses = []
        for prefix in prefixes:
            ip_addr = self._create_ip_address_from_prefix(prefix, circuit.cid, location)
            ip_addresses.append(ip_addr)

        if not ip_addresses:
            self.logger.warning("No IP addresses were created")

        # Step 4: Configure interface
        interface = None
        if ip_addresses:
            interface = self._find_next_available_interface(device)
            self._configure_interface(interface, ip_addresses, circuit.cid, location)

        # Summary
        self.logger.info(f"""
        ✅ Exhibitor connection creation completed:
        
        Circuit: {hl(circuit)}
        Location: {hl(location)}
        Prefixes: {[hl(p) for p in prefixes]}
        IP Addresses: {[hl(ip) for ip in ip_addresses]}
        Device: {hl(device)}
        Interface: {hl(interface) if interface else 'N/A'}
        """)

