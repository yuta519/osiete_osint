from django.core.management.base import BaseCommand

from osiete_osint.apps.service.client import UrlScanClient


class Command(BaseCommand):
    help = 'Return UrlScan results on console'

    def add_arguments(self, parser):
        parser.add_argument('targets', nargs='+', type=str)

    def handle(self, *args, **kwargs) -> str:
        urlscan = UrlScanClient()
        for target in kwargs['targets']:
            response = urlscan.fetch_domain_detail(target)
            print(response)
