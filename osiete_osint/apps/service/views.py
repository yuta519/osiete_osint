from django import template
from django.http import Http404, HttpResponse
from django.template import loader

from rest_framework import generics
from rest_framework import viewsets
from rest_framework import permissions

from osiete_osint.apps.service.serializers import (DataListSerializer, 
                                                    ServiceSerializer)
from osiete_osint.apps.service.models import DataList, Service

# Create your views here.

def top_page(request):
    template = loader.get_template('about.html')
    services = Service.objects.all()
    context = {'services': services}
    return HttpResponse(template.render(context, request))

def datalist_page(request):
    template = loader.get_template("data.html")
    datalist = DataList.objects.all()
    context = {'datalist': datalist}
    return HttpResponse(template.render(context, request))

class api_service_page(viewsets.ModelViewSet):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    # permission_classes = [permissions.IsAuthenticated]

class api_datalist_page(viewsets.ModelViewSet):
    queryset = DataList.objects.all()
    serializer_class = DataListSerializer
    # permission_classes = [permissions.IsAuthenticated]
