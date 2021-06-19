import json

from django.http import Http404, HttpResponse, JsonResponse
from django.template import loader
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, permissions, viewsets
from rest_framework.parsers import JSONParser

from osiete_osint.apps.service.client import UrlScanClient, VirusTotalClient
from osiete_osint.apps.service.models import DataList, Service, VtSummary
from osiete_osint.apps.service.serializers import (
                    DataListSerializer, ServiceSerializer, VtSummarySerializer)

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

@csrf_exempt
def osint_list(request):
    """
    List all OSINTs, or create a new OSINT.
    This method is used by React Frontend(osiete osint react).
    """
    vt = VirusTotalClient()
    if request.method == 'GET':
        osints = DataList.objects.all()
        serializer = DataListSerializer(osints, many=True)
        print(type(serializer))
        return JsonResponse(serializer.data, safe=False)
    elif request.method == 'POST':
        data = JSONParser().parse(request)
        if DataList.objects.filter(data_id=data['data_id']):
            try:
                vtsum = VtSummary.objects.get(osint_id__data_id=data['data_id'])
                vtsum_json = {'data_id': vtsum.osint_id.data_id, 
                    'malicious_level': vtsum.malicious_level, 
                    'owner': vtsum.owner, 'gui': vtsum.gui_url}
                vtsum_json = json.dumps(vtsum_json)
                return HttpResponse(vtsum_json, status=202)
            except:
                raise RuntimeError('No data in VTSummary, but in datalist')
        else:
            serializer = DataListSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(vt.fetch_vt_risk(data['data_id']), status=201)
            return JsonResponse(serializer.errors, status=400)

# @csrf_exempt
def api_urlscan(request):
    """
    List all OSINTs, or create a new OSINT.
    This method is used by React Frontend(osiete osint react).
    """
    vt = VirusTotalClient()
    if request.method == 'GET':
        osints = DataList.objects.all()
        serializer = DataListSerializer(osints, many=True)
        print(type(serializer))
        return JsonResponse(serializer.data, safe=False)
    elif request.method == 'POST':
        data = JSONParser().parse(request)
        if DataList.objects.filter(data_id=data['data_id']):
            try:
                vtsum = VtSummary.objects.get(osint_id__data_id=data['data_id'])
                vtsum_json = {'data_id': vtsum.osint_id.data_id, 
                    'malicious_level': vtsum.malicious_level, 
                    'owner': vtsum.owner, 'gui': vtsum.gui_url}
                vtsum_json = json.dumps(vtsum_json)
                return HttpResponse(vtsum_json, status=202)
            except:
                raise RuntimeError('No data in VTSummary, but in datalist')
        else:
            serializer = DataListSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(vt.fetch_vt_risk(data['data_id']), status=201)
            return JsonResponse(serializer.errors, status=400)


class api_service_page(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    # permission_classes = [permissions.IsAuthenticated]

class api_datalist_page(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = DataList.objects.all()
    serializer_class = DataListSerializer
    # permission_classes = [permissions.IsAuthenticated]

class api_serious_data_list(viewsets.ModelViewSet):
    """
    API endpoint that return dangerous data
    """
    queryset = DataList.objects.filter(malicious_level=1)
    serializer_class = DataListSerializer
    # permission_classes = [permissions.IsAuthenticated]

class api_vt_osint(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = VtSummary.objects.all()
    serializer_class = VtSummarySerializer
    # permission_classes = [permissions.IsAuthenticated]