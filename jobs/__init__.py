"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interfaces import CreateManagementInterface, ConfigureExistingInterfaceForManagement
from .exhibitor_connection import CreateExhibitorConnection, CreateExhibitorConnectionSplit
from .loopback_interfaces import CreateLoopbackInterface, BulkCreateLoopbackInterfaces

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
    CreateExhibitorConnection,
    CreateExhibitorConnectionSplit,
    CreateLoopbackInterface,
    BulkCreateLoopbackInterfaces
]
register_jobs(*jobs)
