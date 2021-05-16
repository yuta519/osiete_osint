from django.contrib import admin

from .models import (DataList, OsintSearchHistory, Service, UrlScan,
                    VtComments, VtSummary,)

# Register your models here.

admin.site.register(DataList)
admin.site.register(OsintSearchHistory)
admin.site.register(Service)
admin.site.register(UrlScan)
admin.site.register(VtComments)
admin.site.register(VtSummary)
