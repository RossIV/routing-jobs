"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interfaces import CreateManagementInterface, ConfigureExistingInterfaceForManagement
from .exhibitor_connection import CreateExhibitorConnection
from .loopback_interfaces import CreateLoopbackInterface, BulkCreateLoopbackInterfaces

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
    CreateExhibitorConnection,
    CreateLoopbackInterface,
    BulkCreateLoopbackInterfaces
]
register_jobs(*jobs)
