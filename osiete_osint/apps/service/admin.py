from django.contrib import admin

from .models import DataList, DataSearchHistry, Service

# Register your models here.

admin.site.register(DataList)
admin.site.register(DataSearchHistry)
admin.site.register(Service)
