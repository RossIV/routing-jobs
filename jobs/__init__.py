"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interfaces import CreateManagementInterface, ConfigureExistingInterfaceForManagement
from .exhibitor_connection import CreateExhibitorConnection
from .loopback_interfaces import CreateLoopbackInterface

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
    CreateExhibitorConnection,
    CreateLoopbackInterface,
]
register_jobs(*jobs)
