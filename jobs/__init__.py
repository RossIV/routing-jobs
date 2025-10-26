"""Jobs declaration for Routing Team"""

from nautobot.core.celery import register_jobs

from .management_interface import CreateManagementInterface, ConfigureExistingInterfaceForManagement

jobs = [
    CreateManagementInterface,
    ConfigureExistingInterfaceForManagement,
]
register_jobs(*jobs)
