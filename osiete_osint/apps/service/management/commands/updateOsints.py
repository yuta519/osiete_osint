from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone

from osiete_osint.apps.service.client import UrlScanClient, VirusTotalClient 
from osiete_osint.apps.service.models import DataList



class Command(BaseCommand):
    help = 'Update all OSINTS in database.'

    def update_osint_of_vt(self, osint) -> None:
        vtclient = VirusTotalClient()
        vtclient.update_vtrisk(osint)

    def update_osint_of_us(self, osint) -> None:
        usclient = UrlScanClient()
        usclient.update_uscaninfo(osint)

    def handle(self, *args, **kwargs) -> None:
        time_threshold = datetime.now() - timedelta(minutes=2)
        # time_threshold = datetime.now() - timedelta(days=3)
        time_threshold = timezone.make_aware(time_threshold)
        all_osints = DataList.objects.filter(last_analyzed__lt=time_threshold)
        for osint in all_osints:
            try:
                print('threshold', time_threshold)
                print(osint, osint.last_analyzed)
                self.update_osint_of_vt(osint)
                self.update_osint_of_us(osint)
                osint.last_analyzed = timezone.now()
                osint.save()
            except KeyError:
                print('Got Restriction of VT API:', osint)
                self.update_osint_of_us(osint)