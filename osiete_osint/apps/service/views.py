from osiete_osint.apps import service
from django import template
from django.http import Http404, HttpResponse
# from django.shortcuts import render
from django.template import loader

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