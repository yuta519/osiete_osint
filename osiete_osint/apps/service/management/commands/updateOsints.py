from django.core.management.base import BaseCommand

from osiete_osint.apps.service.models import (DataList, UrlScan, VtSummary)

class updateOsints(BaseCommand):
    help = 'Update all OSINTS in database.'

    def update_osint_of_vt(self):
        pass