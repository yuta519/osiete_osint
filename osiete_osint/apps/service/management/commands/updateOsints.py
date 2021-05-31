from django.core.management.base import BaseCommand

from osiete_osint.apps.service.client import UrlScanClient, VirusTotalClient 


class Command(BaseCommand):
    help = 'Update all OSINTS in database.'

    def update_osint_of_vt(self) -> None:
        vtclient = VirusTotalClient()
        vtclient.update_vtrisk()

    def update_osint_of_us(self) -> None:
        usclient = UrlScanClient()
        usclient.update_uscaninfo()

    def handle(self, *args, **kwargs) -> None:
        self.update_osint_of_vt()
        self.update_osint_of_us()