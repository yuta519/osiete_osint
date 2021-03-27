from django.core.management.base import BaseCommand

from osiete_osint.apps.service.client import VirusTotalClient


class Command(BaseCommand):
    help = 'Displays current time'

    def get_ipaddress_osint(self):
        virustotal = VirusTotalClient()
        # result = virustotal.get_vt_ipaddress()
        result = virustotal.save_risk()
        return result

    def handle(self, *args, **kwargs):
        # result = self.get_ipaddress_osint()
        # self.stdout.write(f'{result[]}')
        self.get_ipaddress_osint()
