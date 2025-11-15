from django.db import transaction
from functools import lru_cache
import re

from nautobot.dcim.models import Device, Interface, Location
from nautobot.dcim.choices import InterfaceTypeChoices, InterfaceModeChoices
from nautobot.circuits.models import Circuit, Provider, CircuitTermination, CircuitType
from nautobot.ipam.models import Prefix, IPAddress, VRF, VLAN, Namespace
from nautobot.extras.models import Status, Role, Relationship, RelationshipAssociation
from nautobot.apps.jobs import Job, ObjectVar, StringVar, ChoiceVar, BooleanVar, IntegerVar
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
            "role": ["DNOC Switch", "NOC Router", "SCN Router"]
        },
    )

    interface = ObjectVar(
        description="Interface on the selected device to connect to the exhibitor equipment",
        required=True,
        model=Interface,
        display_field="name",
        query_params={
            "device_id": "$device",
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
    def exhibitor_connection_role(self):
        return Role.objects.get(name="Exhibitor Connection (L3)")

    @property
    @lru_cache(maxsize=1)
    def exhibitor_connection_circuit_type(self):
        return CircuitType.objects.get(name="Exhibitor (L3)")

    @property
    @lru_cache(maxsize=1)
    def global_namespace(self):
        return Namespace.objects.get(name="Global")

    def _extract_booth_number(self, location_name):
        """Extract booth number from location name using regex."""
        self.logger.debug(f"Extracting booth number from location name '{location_name}'")
        match = re.search(r'(\d+)', location_name)
        if not match:
            raise RuntimeError(f"Could not extract booth number from location name: {location_name}")
        self.logger.debug(f"Extracted booth number '{match.group(1)}'")
        return match.group(1)

    def _generate_circuit_name(self, booth_number, connection_identifier):
        """Generate circuit name from booth number and connection identifier."""
        self.logger.debug(f"Generating circuit name from booth '{booth_number}' and identifier '{connection_identifier}'")
        return f"{booth_number}-{connection_identifier}"

    def _check_duplicate_circuit(self, circuit_name):
        """Check if a circuit with the same name already exists."""
        self.logger.debug(f"Checking for duplicate circuit with CID '{circuit_name}'")
        existing_circuit = Circuit.objects.filter(cid=circuit_name).first()
        if existing_circuit:
            raise RuntimeError(f"Circuit with CID '{circuit_name}' already exists: {hl(existing_circuit)}")

    def _get_device_rack(self, device):
        """Return the rack associated with the provided device."""
        rack = getattr(device, "rack", None)
        if not rack:
            raise RuntimeError(f"Device {hl(device)} is not assigned to a rack; cannot terminate circuit on A-side.")
        return rack

    def _create_circuit(self, location, device, connection_identifier, speed):
        """Create a circuit for the exhibitor connection."""
        self.logger.debug(f"Creating circuit for location {hl(location)} on device {hl(device)} "
                          f"with identifier '{connection_identifier}' and speed '{speed}'")
        booth_number = self._extract_booth_number(location.name)
        circuit_name = self._generate_circuit_name(booth_number, connection_identifier)

        # Check for duplicates
        self._check_duplicate_circuit(circuit_name)

        # Create circuit
        circuit = Circuit.objects.create(
            cid=circuit_name,
            provider=self.scinet_provider,
            status=self.planned_status,
            circuit_type=self.exhibitor_connection_circuit_type,
            tenant=location.tenant,
            commit_rate=speed,
            description=f"Exhibitor connection for {location.name}",
        )

        self.logger.info(f"➕ Created circuit: {hl(circuit)}")

        # Create terminations
        # A Side: Device location
        CircuitTermination.objects.create(
            circuit=circuit,
            term_side='A',
            location=device.location,
        )

        # Z Side: Booth location
        CircuitTermination.objects.create(
            circuit=circuit,
            term_side='Z',
            location=location,
        )

        self.logger.info(f"➕ Created circuit terminations: A-side={hl(device.location)}, Z-side location={hl(location)}")

        return circuit

    def _find_container_prefix(self, ip_version, connection_type):
        """Find container prefix for allocation."""
        type_filter = "container"
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

        self.logger.debug(f"Found {prefixes.count()} container prefix(es) for IPv{ip_version} and role '{role_filter}'")
        return prefixes.first()

    def _find_next_available_prefix(self, container_prefix, prefix_length):
        """Find the next available prefix of the specified length within the container."""
        self.logger.debug(f"Searching for next available /{prefix_length} inside container {hl(container_prefix)}")
        # Get available prefixes
        available_prefixes = container_prefix.get_available_prefixes()

        # Find the first available block that can fit our desired prefix
        next_prefix = None
        for available_block in available_prefixes.iter_cidrs():
            # Check if this block is large enough (smaller/shorter prefix length = larger block)
            if available_block.prefixlen <= prefix_length:
                # Subnet this block to get a prefix of our desired size
                prefixes = list(available_block.subnet(prefix_length))
                next_prefix = prefixes[0]  # Get the first prefix
                self.logger.debug(f"Found available /{prefix_length}: {next_prefix}")
                return next_prefix

        raise RuntimeError(f"No available /{prefix_length} prefix in container {container_prefix.prefix}")

    def _allocate_prefix(self, circuit, location, ip_version, prefix_length, connection_type, target_vrf):
        """Allocate a new prefix for the circuit."""
        # Only allocate if connection type is Exhibitor
        if connection_type != "Exhibitor":
            self.logger.debug(f"Skipping prefix allocation for connection type '{connection_type}'")
            return None

        if not target_vrf:
            raise RuntimeError("Target VRF must be provided for Exhibitor connections")

        self.logger.debug(f"Allocating IPv{ip_version} /{prefix_length} prefix "
                          f"for circuit {hl(circuit)} using VRF {hl(target_vrf)}")
        # Find container prefix
        container_prefix = self._find_container_prefix(ip_version, connection_type)
        
        # Find next available prefix
        available_subnet = self._find_next_available_prefix(container_prefix, prefix_length)
        
        # Create new prefix
        # Get namespace from container
        namespace = container_prefix.namespace
        
        # Create prefix object
        prefix = Prefix(
            type="network",
            prefix=str(available_subnet),
            ip_version=ip_version,
            status=self.active_status,
            role=self.exhibitor_connection_role,
            description=circuit.cid,
            tenant=location.tenant,
            namespace=namespace,
        )
        prefix.save()

        # Associate prefix with VRF
        prefix.vrfs.set([target_vrf])
        self.logger.info(f"➕ Associated prefix {hl(prefix)} to VRF {hl(target_vrf)}")

        self._relate_prefix_to_circuit(circuit, prefix)

        self.logger.info(f"➕ Allocated prefix: {hl(prefix)}")
        return prefix

    def _get_target_vrf(self, connection_type, firewalled):
        """Return the VRF to use based on connection type and firewall selection."""
        if connection_type == "Exhibitor":
            vrf_name = constants.EXHIBITOR_FIREWALLED_VRF if firewalled else constants.EXHIBITOR_UNFIREWALLED_VRF
        elif connection_type == "NRE":
            vrf_name = constants.NRE_VRF
        else:
            raise RuntimeError(f"Invalid connection type: {connection_type}")

        self.logger.debug(f"Fetching VRF '{vrf_name}' for prefix allocation")
        try:
            return VRF.objects.get(name=vrf_name)
        except VRF.DoesNotExist:
            raise RuntimeError(f"VRF '{vrf_name}' not found; cannot continue")

    def _relate_prefix_to_circuit(self, circuit, prefix):
        """Associate prefix to circuit via custom relationship."""
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

    def _create_ip_address_from_prefix(self, prefix, circuit_name, location):
        """Create an IP address from the prefix (first host or ::1 for IPv6)."""
        self.logger.debug(f"Creating IP address from prefix {hl(prefix)} for circuit '{circuit_name}'")
        prefix_network = ip_network(str(prefix.prefix))
        self.logger.debug(f"Prefix network: {prefix_network}")
        ip_address_str = f"{prefix_network.network_address + 1}/{prefix.prefix_length}"

        self.logger.debug(f"Creating IP address: {ip_address_str}")
        self.logger.debug(f"IP version: {prefix.ip_version}")
        self.logger.debug(f"Status: {self.active_status}")
        self.logger.debug(f"Description: {circuit_name}")
        self.logger.debug(f"Tenant: {location.tenant}")
        # Create IP address
        ip_address = IPAddress.objects.create(
            address=ip_address_str,
            ip_version=prefix.ip_version,
            status=self.active_status,
            description=circuit_name,
            tenant=location.tenant
        )

        # Set DNS name
        booth_number = self._extract_booth_number(location.name)
        self.logger.debug(f"Booth number: {booth_number}")
        self.logger.debug(f"Circuit name: {circuit_name}")
        # Extract connection identifier from circuit name
        conn_id = circuit_name.split('-')[1] if '-' in circuit_name else 'A'
        dns_name = f"{conn_id}01.{booth_number}.{constants.MANAGEMENT_DNS_DOMAIN}"
        ip_address.dns_name = dns_name
        ip_address.save()

        self.logger.info(f"➕ Created IP address: {hl(ip_address)}")
        return ip_address

    def _configure_interface(self, interface, ip_addresses, circuit_name, location, vrf):
        """Configure interface with IP addresses and description."""
        self.logger.debug(f"Configuring interface {hl(interface)} with {len(ip_addresses)} IP(s) for circuit '{circuit_name}'")
        self.logger.debug(f"Setting interface VRF to {hl(vrf) if vrf else 'None'} based on prefix configuration")
        
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
            subnet_size_ipv4, device, interface, speed, connection_type, firewalled):
        """Main execution method."""
        self.logger.info(f"🚀 Starting exhibitor connection creation for location: {hl(location)}")

        target_vrf = self._get_target_vrf(connection_type, firewalled)

        # Step 1: Create circuit
        circuit = self._create_circuit(location, device, connection_identifier, speed)
        
        # Step 2: Allocate prefixes
        prefixes = []
        if ipv4_enabled and connection_type == "Exhibitor":
            prefix_ipv4 = self._allocate_prefix(
                circuit, location, 4, int(subnet_size_ipv4), connection_type, target_vrf
            )
            if prefix_ipv4:
                prefixes.append(prefix_ipv4)
        
        if ipv6_enabled and connection_type == "Exhibitor":
            # Default IPv6 prefix length (typically /64 for LANs)
            prefix_ipv6 = self._allocate_prefix(
                circuit, location, 6, 64, connection_type, target_vrf
            )
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
        configured_interface = None
        if ip_addresses:
            if interface.device_id != device.id:
                raise RuntimeError(f"Selected interface {hl(interface)} does not belong to device {hl(device)}")

            prefix_vrf = None
            if prefixes:
                prefix_vrf = prefixes[0].vrfs.first()
                if not prefix_vrf:
                    self.logger.warning(f"No VRF associated with prefix {hl(prefixes[0])}; interface VRF will be left unset")

            configured_interface = self._configure_interface(interface, ip_addresses, circuit.cid, location, prefix_vrf)

        # Summary
        self.logger.info(f"""
        ✅ Exhibitor connection creation completed:
        
        Circuit: {hl(circuit)}
        Location: {hl(location)}
        Prefixes: {[hl(p) for p in prefixes]}
        IP Addresses: {[hl(ip) for ip in ip_addresses]}
        Device: {hl(device)}
        Interface: {hl(configured_interface) if configured_interface else 'N/A'}
        """)


class CreateExhibitorConnectionSplit(CreateExhibitorConnection):
    """
    Create an exhibitor connection where routing and switching functions live on separate devices.
    """

    # Disable base job inputs that aren't used in this split workflow
    ipv4_enabled = None
    ipv6_enabled = None
    subnet_size_ipv4 = None
    device = None
    interface = None

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

    ipv4_prefix_input = StringVar(
        description="IPv4 prefix to assign (e.g., 192.0.2.0/30)",
        required=False,
    )

    ipv6_prefix_input = StringVar(
        description="IPv6 prefix to assign (e.g., 2001:db8::/64)",
        required=False,
    )

    router_device = ObjectVar(
        description="Router device that will host the routed subinterface",
        required=True,
        model=Device,
        display_field="name",
        query_params={
            "role": ["DNOC Switch", "NOC Router", "SCN Router"]
        },
    )

    router_interface = ObjectVar(
        description="Parent interface on the router device",
        required=True,
        model=Interface,
        display_field="name",
        query_params={
            "device_id": "$router_device",
        },
    )

    router_subinterface_id = IntegerVar(
        description="Numeric identifier used for the new router subinterface and VLAN",
        required=True,
    )

    switch_device = ObjectVar(
        description="Switch device that connects to the exhibitor equipment",
        required=True,
        model=Device,
        display_field="name",
        query_params={
            "role": ["DNOC Switch", "NOC Router", "SCN Router"]
        },
    )

    switch_interface = ObjectVar(
        description="Switch interface that connects to the exhibitor equipment",
        required=True,
        model=Interface,
        display_field="name",
        query_params={
            "device_id": "$switch_device",
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
        name = "Create Exhibitor Connection (Split Route/Switch)"
        description = "Create an exhibitor connection where routing and switching functions live on separate devices."
        has_sensitive_variables = False

    def _get_or_create_manual_prefix(self, prefix_input, expected_version, circuit, location, target_vrf):
        """Create a prefix object from user-provided input."""
        cleaned_input = (prefix_input or "").strip()
        if not cleaned_input:
            return None

        try:
            network = ip_network(cleaned_input, strict=True)
        except ValueError as exc:
            raise RuntimeError(f"Invalid IPv{expected_version} prefix '{cleaned_input}': {exc}")

        if network.version != expected_version:
            raise RuntimeError(f"Provided prefix '{cleaned_input}' is IPv{network.version}, expected IPv{expected_version}")

        canonical_prefix = str(network)
        if Prefix.objects.filter(prefix=canonical_prefix).exists():
            raise RuntimeError(f"Prefix {canonical_prefix} already exists in Nautobot")

        prefix = Prefix(
            type="network",
            prefix=canonical_prefix,
            ip_version=network.version,
            status=self.active_status,
            role=self.exhibitor_connection_role,
            description=circuit.cid,
            tenant=location.tenant,
            namespace=self.global_namespace,
        )
        prefix.save()
        prefix.vrfs.set([target_vrf])
        self._relate_prefix_to_circuit(circuit, prefix)
        self.logger.info(f"➕ Created manual prefix {hl(prefix)}")
        return prefix

    def _get_vlan(self, vlan_id):
        """Validate VLAN existence."""
        vlan = VLAN.objects.filter(vid=vlan_id).first()
        if not vlan:
            raise RuntimeError(f"VLAN with ID {vlan_id} does not exist in Nautobot")
        return vlan

    def _create_router_subinterface(self, router_device, parent_interface, subinterface_id, circuit_name, location, vlan):
        """Create the router subinterface used for routed connectivity."""
        if parent_interface.device_id != router_device.id:
            raise RuntimeError(f"Interface {hl(parent_interface)} is not on router device {hl(router_device)}")

        subinterface_name = f"{parent_interface.name}.{subinterface_id}"
        existing = Interface.objects.filter(device=router_device, name=subinterface_name).first()
        if existing:
            raise RuntimeError(f"Subinterface {subinterface_name} already exists on device {hl(router_device)}")

        subinterface = Interface.objects.create(
            device=router_device,
            name=subinterface_name,
            parent_interface=parent_interface,
            type=InterfaceTypeChoices.TYPE_VIRTUAL,
            status=self.planned_status,
            description=f"{circuit_name}: {location.tenant.name if location.tenant else 'Unknown'}",
        )
        subinterface.tagged_vlans.set([vlan])
        self.logger.info(f"➕ Created router subinterface {hl(subinterface)} tagged for VLAN {hl(vlan)}")
        return subinterface

    def _configure_switch_customer_interface(self, switch_device, interface, circuit_name, location, vlan):
        """Configure the switch-facing interface for the exhibitor."""
        if interface.device_id != switch_device.id:
            raise RuntimeError(f"Interface {hl(interface)} is not on switch device {hl(switch_device)}")

        interface.description = f"{circuit_name}: {location.tenant.name if location.tenant else 'Unknown'}"
        interface.mode = InterfaceModeChoices.MODE_ACCESS
        interface.untagged_vlan = vlan
        interface.tagged_vlans.clear()
        interface.save()

        self.logger.info(f"✅ Configured switch interface {hl(interface)} as access with VLAN {hl(vlan)}")
        return interface

    @transaction.atomic
    def run(
        self,
        location,
        connection_identifier,
        ipv4_prefix_input,
        ipv6_prefix_input,
        router_device,
        router_interface,
        router_subinterface_id,
        switch_device,
        switch_interface,
        speed,
        connection_type,
        firewalled,
    ):
        """Main execution method for split router/switch connections."""
        self.logger.info(f"🚀 Starting split exhibitor connection creation for location: {hl(location)}")

        if not (ipv4_prefix_input or ipv6_prefix_input):
            raise RuntimeError("You must provide at least one IPv4 or IPv6 prefix")

        target_vrf = self._get_target_vrf(connection_type, firewalled)
        vlan = self._get_vlan(router_subinterface_id)

        circuit = self._create_circuit(location, router_device, connection_identifier, speed)

        prefixes = []
        if ipv4_prefix_input:
            prefix_ipv4 = self._get_or_create_manual_prefix(ipv4_prefix_input, 4, circuit, location, target_vrf)
            if prefix_ipv4:
                prefixes.append(prefix_ipv4)

        if ipv6_prefix_input:
            prefix_ipv6 = self._get_or_create_manual_prefix(ipv6_prefix_input, 6, circuit, location, target_vrf)
            if prefix_ipv6:
                prefixes.append(prefix_ipv6)

        if not prefixes:
            raise RuntimeError("No prefixes were created; cannot continue")

        ip_addresses = []
        for prefix in prefixes:
            ip_addr = self._create_ip_address_from_prefix(prefix, circuit.cid, location)
            ip_addresses.append(ip_addr)

        router_subinterface = self._create_router_subinterface(
            router_device,
            router_interface,
            router_subinterface_id,
            circuit.cid,
            location,
            vlan,
        )

        configured_router_interface = self._configure_interface(
            router_subinterface,
            ip_addresses,
            circuit.cid,
            location,
            target_vrf,
        )

        configured_switch_interface = self._configure_switch_customer_interface(
            switch_device,
            switch_interface,
            circuit.cid,
            location,
            vlan,
        )

        self.logger.info(f"""
        ✅ Split exhibitor connection creation completed:
        
        Circuit: {hl(circuit)}
        Location: {hl(location)}
        Prefixes: {[hl(p) for p in prefixes]}
        IP Addresses: {[hl(ip) for ip in ip_addresses]}
        Router Device: {hl(router_device)}
        Router Interface: {hl(configured_router_interface)}
        Switch Device: {hl(switch_device)}
        Switch Interface: {hl(configured_switch_interface)}
        VLAN: {hl(vlan)}
        """)
