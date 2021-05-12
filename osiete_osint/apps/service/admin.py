from django.contrib import admin

from .models import DataList, OsintSearchHistory, Service

# Register your models here.

admin.site.register(DataList)
admin.site.register(OsintSearchHistory)
admin.site.register(Service)
