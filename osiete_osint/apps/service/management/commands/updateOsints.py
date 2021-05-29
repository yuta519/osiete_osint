from django.core.management.base import BaseCommand

from osiete_osint.apps.service.models import (DataList, UrlScan, VtSummary)

class Command(BaseCommand):
    help = 'Update all OSINTS in database.'

    def __init__(self):
        self.osints = DataList.objects.all()

    def update_osint_of_vt(self):
        print(self.osints)

    def handle(self, *args, **kwargs) -> None:
        self.update_osint_of_vt()
        pass