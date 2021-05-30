from django.core.management.base import BaseCommand

from osiete_osint.apps.service.client import VirusTotalClient


class Command(BaseCommand):
    help = 'Displays current time'

    def fetch_osint_risk(self):
        virustotal = VirusTotalClient()
        result = virustotal.fetch_unknown_vtrisk()
        return result

    def handle(self, *args, **kwargs):
        # result = self.get_ipaddress_osint()
        # self.stdout.write(f'{result[]}')
        self.fetch_osint_risk()
