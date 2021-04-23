from ipaddress import AddressValueError, IPv4Network
import logging
import re
import sys
from urllib.parse import urlparse

from django.utils import timezone
import requests

from osiete_osint.apps.service.models import DataList, Service
# from osiete_osint.apps.service.views import datalist_page


logger = logging.getLogger(__name__)


class AbstractBaseClient():
    """ """
    def __init__(self):
        self.headers = {'user-agent': 'osiete/1.0'}

    def check_on_db(self, data):
        DataList.objects.get_or_create(data_id=data, 
            defaults={'data_id': data, 'malicious_level': DataList.UNKNOWN})

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
        self.headers['x-apikey'] =('1c2fb58f31b82e29a93c6a87392b21bc3b64247b8a'
                                    'f0a42788a7dd03d6728c57')
        self.vt = Service.objects.get(slug='vt')

    # TODO : Change method name
    # TODO : Using vt.py for handling IP, Domain, URL
    def crawl_data(self, target):
        """ """
        # Check whether target is ipaddress or not
        try:
            IPv4Network(target)
            # print(f"IP: {result}")
            return self.get_vt_ipaddress(target)
        except AddressValueError:
            # Check whether target is URL or not
            pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
            # is_url = re.match(pattern, target)
            if re.match(pattern, target):
                print("URL")
                return self.get_vt_domain(target)
            else:
                print("Hash")
                # return self.get_vt_hash()

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

    def get_vt_domain(self, domain):
        self.check_on_db(data=domain)
        domain = urlparse(domain).netloc        
        base = f'{self.vt.url}domains/'
        response = [self.request(f'{base}{domain}'), 
                    # self.request(f'{base}{ip}/comments'),
                    # self.request(f'{base}{ip}/historical_whois'),
                    # self.request(f'{base}{ip}/resolution')
                    ]
        # TODO@yuta create historical and resolution
        result = self.parse_summary_domain(response[0])
        # result['comments'] = self.parse_comments_of_ipaddress(response[1])
        return result
    
    def parse_summary_domain(self, res):
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
        gui = ('https://www.virustotal.com/gui/domain/'
                f'{res["data"]["id"]}/detection')
        result = {'owner': owner,'malicious_level': malicious_level, 
                    'gui': gui, 'type': DataList.DOM}
        return result

    def get_vt_hash(self):
        pass