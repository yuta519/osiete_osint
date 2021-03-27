# coding: utf-8
from ipaddress import AddressValueError, IPv4Network
import logging
from osiete_osint.apps.service.views import datalist_page
import re

from django.utils import timezone
import requests

from osiete_osint.apps.service.models import DataList, Service


logger = logging.getLogger(__name__)


class AbstractBaseClient:
    """ """
    def __init__(self):
        self.headers = {'user-agent': 'osiete/1.0'}

    def check_on_db(self, data):
        DataList.objects.get_or_create(data_id=data, 
            defaults={'data_id': data, 'malicious_level': DataList.UN})

    def save_risk(self):
        not_yet_investgated = DataList.objects.filter(malicious_level=0)
        for target in not_yet_investgated:
            result = self.crawl_data(target.data_id)
            target_data = DataList.objects.get(data_id=target)
            target_data.analyzing_type = result['type']
            target_data.gui_url = result['gui']
            target_data.last_analyzed = timezone.now()
            target_data.malicious_level = result['malicious_level']
            target_data.save()


class VirusTotalClient(AbstractBaseClient):
    """ """
    def __init__(self):
        super().__init__()
        self.headers['x-apikey'] =('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
        self.vt = Service.objects.get(slug='vt')

    def crawl_data(self, target):
        """ """
        # Check whether target is ipaddress or not
        try:
            IPv4Network(target)
            result =self.get_vt_ipaddress(target)
            # print(f"IP: {result}")
            # return self.get_vt_ipaddress(target)
            return result
        except AddressValueError:
            # Check whether target is URL or not
            pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
            if re.match(pattern, target):
                # print("URL")
                return self.get_vt_url()
            else:
                # print("Hash")
                return self.get_vt_hash()

    def request(self, endpoint):
        response = requests.get(endpoint, headers=self.headers)
        result = response.json()
        # print(result)
        return result

    def get_vt_ipaddress(self, ip):
        self.check_on_db(data=ip)
        base = f'{self.vt.url}ip_addresses/'
        response = [self.request(f'{base}{ip}'), 
                    self.request(f'{base}{ip}/comments'),
                    # self.request(f'{base}{ip}/historical_whois'),
                    # self.request(f'{base}{ip}/resolution')
                    ]
        # TODO@yuta create historical and resolution
        result = self.parse_summary_ipaddress(response[0])
        result['comments'] = self.parse_comments_of_ipaddress(response[1])
        return result

    def parse_summary_ipaddress(self, res):
        """ """
        attributes = res['data']['attributes']
        analysis = res['data']['attributes']['last_analysis_stats']

        if analysis['malicious'] > 0:
            malicious_level = DataList.MAL
        elif (analysis['malicious'] == 0 and analysis['suspicious'] > 0):
            malicious_level = DataList.SUS
        else:
            malicious_level = DataList.SA
        owner = attributes['as_owner'] if 'as_owner' in attributes else 'null'
        gui = ('https://www.virustotal.com/gui/ip-address/'
                    f'{res["data"]["id"]}/detection')
        result = {'owner': owner,'malicious_level': malicious_level, 
                    'gui': gui, 'type': DataList.IP}
        return result

    def parse_comments_of_ipaddress(self, res):        
        result = [r['attributes']['text'] for r in res['data']]
        return result
    
    def parse_historical_whois_of_ipaddress(self, res):  
        pass
    #     result = [r['attributes']['text'] for r in res['data']]
    #     return result

    def parse_resolution_of_ipaddress(self, res):  
        pass
    #     result = [r['attributes']['text'] for r in res['data']]
    #     return result

    def get_vt_url(self):
        pass

    def get_vt_hash(self):
        pass