"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interfaces import CreateManagementInterface, ConfigureExistingInterfaceForManagement
from .exhibitor_connection import (
    CreateExhibitorConnection,
    CreateExhibitorConnectionAdvanced,
    CreateExhibitorConnectionSplit,
    CreateExhibitorConnectionSplitBulk,
)
from .loopback_interfaces import CreateLoopbackInterface, BulkCreateLoopbackInterfaces

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
    CreateExhibitorConnection,
    CreateExhibitorConnectionAdvanced,
    CreateExhibitorConnectionSplit,
    CreateExhibitorConnectionSplitBulk,
    CreateLoopbackInterface,
    BulkCreateLoopbackInterfaces
]
register_jobs(*jobs)
