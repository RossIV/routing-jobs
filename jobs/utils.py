import re
from nautobot.core.templatetags.helpers import hyperlinked_object

def hl(obj, label=None):
    """Highlight obj for logging."""
    if not obj:
        return "N/A"
    html = hyperlinked_object(obj)

    if label:
        # Replace the text between >...</a>
        html = re.sub(r'>(.*?)</a>', f'>{label}</a>', html)
    return html