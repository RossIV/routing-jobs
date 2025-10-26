"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interfaces import CreateManagementInterface, ConfigureExistingInterfaceForManagement

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
]
register_jobs(*jobs)
