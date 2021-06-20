from rest_framework import serializers

from osiete_osint.apps.service.models import (DataList, Service, UrlScan, 
                                              VtSummary)


class ServiceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Service
        fields = ('name', 'slug', 'url')


class DataListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataList
        fields = ('data_id', 'analyzing_type', 'last_analyzed', 
                  'malicious_level')


class UrlScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = UrlScan
        fields = ('osint_id', 'date', 'domain', 'primary_ip', 'server', 'asn', 
                  'asnname', 'ptr', 'screenshot') 


class VtSummarySerializer(serializers.ModelSerializer):
    data = DataListSerializer(read_only=True)
    class Meta:
        model = VtSummary
        fields = ('__all__')
