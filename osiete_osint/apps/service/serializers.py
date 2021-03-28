from rest_framework import serializers

from osiete_osint.apps.service.models import DataList, Service


class ServiceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Service
        fields = ('name', 'slug', 'url')


class DataListSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = DataList
        fields = ('data_id', 'analyzing_type', 'gui_url', 'last_analyzed', 
                    'malicious_level')
