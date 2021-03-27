from django.core.management.base import BaseCommand

from osiete_osint.apps.service.client import VirusTotalClient


class Command(BaseCommand):
    help = 'Return VirusTotal results on console'

    def add_arguments(self, parser):
        parser.add_argument('targets', nargs='+', type=str)

    def handle(self, *args, **kwargs):
        virustotal = VirusTotalClient()
        for target in kwargs['targets']:
            print(virustotal.get_vt_ipaddress(ip=target))
