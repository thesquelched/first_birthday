from smtplib import SMTP
from email.mime.text import MIMEText

import logging


class Emailer(object):
    """Base class for emailers"""

    def __init__(self, sender, host=None, logger=None):
        if host is None:
            host = 'localhost'
        if logger is None:
            logger = logging.getLogger(__name__)

        self.sender = sender
        self.host = host

        self.logger = logger

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def send(self, to, subject, content):
        """Send an email"""
        raise NotImplementedError

    def message(self, to, subject, content):
        msg = MIMEText(content)

        msg['From'] = self.sender
        msg['To'] = to
        msg['Subject'] = subject

        return msg


class SmtpEmailer(Emailer):
    """Email via sendmail"""

    def send(self, to, subject, content):
        msg = self.message(to, subject, content)
        self.smtp.sendmail(self.sender, to, msg.as_string())

    def __enter__(self):
        self.smtp = SMTP(self.host)

    def __exit__(self, type, value, traceback):
        self.smtp.quit()


class MockEmailer(Emailer):
    """Mock emailer class that just logs email to send"""

    def send(self, to, subject, content):
        msg = self.message(to, subject, content)
        self.logger.info('Sending email:\n{}'.format(msg.as_string()))
