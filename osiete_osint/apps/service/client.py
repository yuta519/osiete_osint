from datetime import datetime
from ipaddress import AddressValueError, IPv4Address
import logging
import re
from urllib import parse
from urllib.parse import urlparse

from django.utils import timezone
import requests

from osiete_osint.apps.service.models import (DataList, Service, UrlScan,
                                            VtSummary)


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
    
    def judge_osint_type(self, target):
        IP, URL, HASH = 1, 2, 3
        # Check whether target osint is ipaddress or not
        try:
            IPv4Address(target)
            osint_type = IP
        except AddressValueError:
            # Check whether target osint is URL or not
            pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
            osint_type = URL if re.match(pattern, target) else HASH
        return osint_type

    def extract_url_domain(self, target_url):
        """Extract domain from url given by user."""
        url_pattern = 'https?://[\w/:%#\$&\?\(\)~\.=\+\-]+'
        if re.match(url_pattern, target_url):
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            return domain
        else:
            return target_url

    def assess_osint_risk(self, osint):
        has_analyzed, osint_res = self.has_analyzed(osint)
        if has_analyzed == 1:
            return osint_res.values('data_id', 'gui_url', 'malicious_level')
        else:
            res = self.assess_vt_risk(osint)
            DataList.objects.create(data_id=osint, analyzing_type=res['type'], 
                                    gui_url=res['gui'], 
                                    malicious_level=res['malicious_level'])
            return res

    # TODO: chnage Method Name like crawl_osint_risk
    # def save_risk(self):
    #     not_yet_investgated = DataList.objects.filter(malicious_level=0)
    #     print(not_yet_investgated)
    #     for target in not_yet_investgated:
    #         vt_result = self.assess_vt_risk(target.data_id)
    #         print(target, vt_result)
    #         target_data = DataList.objects.get(data_id=target)
    #         target_data.analyzing_type = vt_result['type']
    #         target_data.gui_url = vt_result['gui']
    #         target_data.last_analyzed = timezone.now()
    #         target_data.malicious_level = vt_result['malicious_level']
    #         target_data.save()
    #         vt_osint = VtSummary(osint_id=target_data, owner=vt_result['owner'], 
    #                             gui_url=vt_result['gui'],
    #                             malicious_level=vt_result['malicious_level'],
    #                             )
    #         vt_osint.save()
            # us_osint = UrlScan(osint_id=target_data, date)


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
        osint_type = self.judge_osint_type(osint)
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
        elif analysis['malicious'] == 0 and analysis['suspicious'] > 0:
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
            raise RuntimeError('This IoC is not searched VT yet.')

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

    def get_vt_hash(self, hash):
        pass

    # TODO: chnage Method Name like crawl_osint_risk
    def save_risk(self):
        not_yet_investgated = DataList.objects.filter(malicious_level=0)
        print(not_yet_investgated)
        for target in not_yet_investgated:
            vt_result = self.assess_vt_risk(target.data_id)
            print(target, vt_result)
            target_data = DataList.objects.get(data_id=target)
            target_data.analyzing_type = vt_result['type']
            target_data.gui_url = vt_result['gui']
            target_data.last_analyzed = timezone.now()
            target_data.malicious_level = vt_result['malicious_level']
            target_data.save()
            vt_osint = VtSummary(osint_id=target_data, owner=vt_result['owner'], 
                                gui_url=vt_result['gui'],
                                malicious_level=vt_result['malicious_level'],
                                )
            vt_osint.save()


class UrlScanClient(AbstractBaseClient):
    def __init__(self):
        super().__init__()
        self.headers = {'API-Key':'a6472481-0a4c-4c13-9f2b-aaf391f140dc',
                        'Content-Type':'application/json'}
        self.us = Service.objects.get(slug='us')
        
    def fetch_domain_detail(self, target_osint):
        target_osint = self.extract_url_domain(target_osint)
        endpoint = f'{self.us.url}/search/?q=domain:{target_osint}'
        response = requests.get(endpoint, headers=self.headers).json()
        return self.parse_domain_detail(response)
    
    def parse_domain_detail(self, res) -> dict:
        try:
            recent_result = res['results'][0]
        except KeyError:
            raise RuntimeError('There is not IoC in UrlScan.')
        recent_result['indexedAt'] = re.sub(
            '\.\d*\.*Z\Z', '', recent_result['indexedAt'])
        parsed_result = {'date': datetime.fromisoformat(recent_result['indexedAt']), 
                        'ipaddress': recent_result['page']['ip'],
                        'domain': recent_result['page']['domain'],
                        'server': recent_result['page']['server'],
                        # 'asnname': recent_result['page']['asnname'],
                        'asn': recent_result['page']['asn'],
                        'ptr': recent_result['page']['ptr'],
                        'screenshot': recent_result['screenshot']}
        return parsed_result

    def save_osint_info(self, target_osint) -> None:
        us_result = self.fetch_domain_detail(target_osint)
        osint_id = DataList.objects.get(data_id=target_osint)
        us_osint = UrlScan(osint_id=osint_id, date=us_result['date'],
                            domain=us_result['domain'], 
                            primary_ip=us_result['ipaddress'],
                            server=us_result['server'], asn=us_result['asn'],
                            # asnname=us_result['asnname'], 
                            ptr=us_result['ptr'], 
                            screenshot=us_result['screenshot'])
        us_osint.save()