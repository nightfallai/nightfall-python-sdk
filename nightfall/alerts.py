from dataclasses import dataclass

from typing import List, Tuple, Optional

@dataclass
class SlackAlert:
    """SlackAlert contains the configuration required to allow clients to send asynchronous alerts to a Slack
       workspace when findings are detected. Note that in order for Slack alerts to be delivered to your workspace,
       you must use authenticate Nightfall to your Slack workspace under the Settings menu on the Nightfall Dashboard.

       Currently, Nightfall supports delivering alerts to public channels, formatted like "#general".
       Alerts are only sent if findings are detected.
    Attributes:
        target (str): the channel name, formatted like "#general".
    """
    target: str

    def as_dict(self):
        return {"target": self.target}

@dataclass
class EmailAlert:
    """EmailAlert contains the configuration required to allow clients to send an asynchronous email message
       when findings are detected. The findings themselves will be delivered as a file attachment on the email.
       Alerts are only sent if findings are detected.
    Attributes:
        address (str): the email address to which alerts should be sent.
    """
    address: str

    def as_dict(self):
        return {"address": self.address}

@dataclass
class WebhookAlert:
    """WebhookAlert contains the configuration required to allow clients to send a webhook event to an
       external URL when findings are detected. The URL provided must (1) use the HTTPS scheme, (2) have a
       route defined on the HTTP POST method, and (3) return a 200 status code upon receipt of the event.
        
       In contrast to other platforms, when using the file scanning APIs, an alert is also sent to this webhook
       *even when there are no findings*.
    Attributes:
        address (str): the URL to which alerts should be sent.
    """
    address: str

    def as_dict(self):
        return {"address": self.address}

@dataclass
class AlertConfig:
    """AlertConfig allows clients to specify where alerts should be delivered when findings are discovered as
       part of a scan. These alerts are delivered asynchronously to all destinations specified in the object instance.
    Attributes:
        slack (SlackAlert): Send alerts to a Slack workspace when findings are detected.
        email (EmailAlert): Send alerts to an email address when findings are detected.
        url (WebhookAlert): Send an HTTP webhook event to a URL when findings are detected.
    """
    slack: Optional[SlackAlert] = None
    email: Optional[EmailAlert] = None
    url: Optional[WebhookAlert] = None

    def as_dict(self):
        result = {}
        if self.slack:
            result["slack"] = self.slack.as_dict()
        if self.email:
            result["email"] = self.email.as_dict()
        if self.url:
            result["url"] = self.url.as_dict()
        return result

