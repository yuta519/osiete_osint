from ipaddress import AddressValueError, IPv4Network, IPv4Address
import logging
import re
from urllib.parse import urlparse

from django.utils import timezone
import requests

from osiete_osint.apps.service.models import DataList, Service


logger = logging.getLogger(__name__)


class AbstractBaseClient():
    """ """
    def __init__(self):
        self.headers = {'user-agent': 'osiete/1.0'}
    
    def has_analyzed(self, osint):
        not_yet, already_analyzed = 0, 1
        is_osint_in_db = DataList.objects.filter(data_id=osint)
        has_analyzed = already_analyzed if is_osint_in_db else not_yet
        return has_analyzed, is_osint_in_db

    # TODO : create new method to analy
    def check_on_db(self, data):
        DataList.objects.get_or_create(data_id=data, defaults={'data_id': data,
            'malicious_level': DataList.UNKNOWN})
    
    def find_osint_type(self, target):
        IP, URL, HASH = 1, 2, 3
        # Check whether target is ipaddress or not
        try:
            IPv4Address(target)
            osint_type = IP
        except AddressValueError:
            # Check whether target is URL or not
            pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
            osint_type = URL if re.match(pattern, target) else HASH
        return osint_type

    def assess_osint_risk(self, osint):
        has_analyzed, osint_res = self.has_analyzed(osint)
        if has_analyzed == 1:
            return osint_res.values('data_id', 'gui_url', 'malicious_level')
        else:
            res = self.assess_vt_risk(osint)
            DataList.objects.create(data_id=osint, analyzing_type=res['type'], 
                gui_url=res['gui'], malicious_level=res['malicious_level'])
            return res

    # TODO: chnage Method Name like crawl_osint_risk
    def save_risk(self):
        not_yet_investgated = DataList.objects.filter(malicious_level=0)
        print(not_yet_investgated)
        for target in not_yet_investgated:
            result = self.assess_vt_risk(target.data_id)
            print(result)
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
        self.headers['x-apikey'] = ('1c2fb58f31b82e29a93c6a87392b21bc3b64247b8'
                                    'af0a42788a7dd03d6728c57')
        self.vt = Service.objects.get(slug='vt')

    # TODO: Change method name
    # TODO: Using vt.py for handling IP, Domain, URL
    def assess_vt_risk(self, osint):
        """ """
        osint_type = self.find_osint_type(osint)
        if osint_type == 1:
            return self.get_vt_ipaddress(osint)
        elif osint_type == 2:
            return self.get_vt_domain(osint)
        elif osint_type == 3:
            return self.get_vt_hash(osint)

    def request(self, endpoint):
        response = requests.get(endpoint, headers=self.headers).json()
        return response

    def get_vt_ipaddress(self, ip):
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
        domain = urlparse(domain).netloc        
        base = f'{self.vt.url}domains/'
        response = [self.request(f'{base}{domain}'), 
                    # self.request(f'{base}{ip}/comments'),
                    # self.request(f'{base}{ip}/historical_whois'),
                    # self.request(f'{base}{ip}/resolution')
                    ]
        if response[0].get('error') != None:
            raise Exception('Your Input is invalid.')

        # TODO@yuta create historical and resolution
        result = self.parse_summary_domain(response[0])
        # result['comments'] = self.parse_comments_of_ipaddress(response[1])
        return result
    
    def parse_summary_domain(self, res):
        """ """
        try:
            attributes = res['data']['attributes']
            analysis = res['data']['attributes']['last_analysis_stats']
        except KeyError:
            raise('This IoC is not searched VT yet.')

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