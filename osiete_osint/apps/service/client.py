from datetime import datetime
from ipaddress import AddressValueError, IPv4Address
import logging
import re
import time
from urllib.parse import urlparse

from django.db.utils import IntegrityError
from django.utils import timezone
import requests

from osiete_osint.apps.service.models import (
    DataList, Service, UrlScan, VtSummary)


logger = logging.getLogger(__name__)


class AbstractBaseClient():
    """ """
    def __init__(self):
        self.headers = {'user-agent': 'osiete/1.0'}
        self.url_pattern = 'https?://[\w/:%#\$&\?\(\)~\.=\+\-]+'

    def has_analyzed(self, osint) -> tuple:
        not_yet, already_analyzed = 0, 1
        is_osint_in_db = DataList.objects.filter(data_id=osint)
        has_analyzed = already_analyzed if is_osint_in_db else not_yet
        return has_analyzed, is_osint_in_db
    
    def judge_osint_type(self, target) -> int:
        IP, URL, HASH = 1, 2, 3
        # Check whether target osint is ipaddress or not
        try:
            IPv4Address(target)
            osint_type = IP
        except AddressValueError:
            # Check whether target osint is URL or not
            osint_type = URL if re.match(self.url_pattern, target) else HASH
        return osint_type

    def extract_url_domain(self, target_url) -> str:
        """Extract domain from url given by user."""
        if re.match(self.url_pattern, target_url):
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            return domain
        else:
            return target_url

    def assess_osint_risk(self, osint) -> dict:
        has_analyzed, osint_res = self.has_analyzed(osint)
        if has_analyzed == 1:
            return osint_res.values('data_id','analyzing_type','malicious_level')
        else:
            res = self.fetch_vt_risk(osint)
            DataList.objects.create(data_id=osint, analyzing_type=res['type'], 
                                    malicious_level=res['malicious_level'])
            return res


class VirusTotalClient(AbstractBaseClient):
    """ """
    def __init__(self):
        super().__init__()
        self.headers['x-apikey'] = ('1c2fb58f31b82e29a93c6a87392b21bc3b64247b8'
                                    'af0a42788a7dd03d6728c57')
        self.vt = Service.objects.get(slug='vt')

    # TODO: Change method name
    # TODO: Using vt.py for handling IP, Domain, URL
    def fetch_vt_risk(self, osint) -> dict:
        """ """
        osint_type = self.judge_osint_type(osint)
        if osint_type == 1:
            return self.get_vt_ipaddress(osint)
        elif osint_type == 2:
            return self.get_vt_domain(osint)
        elif osint_type == 3:
            return self.get_vt_hash(osint)

    def request(self, endpoint) -> dict:
        response = requests.get(endpoint, headers=self.headers).json()
        return response

    def get_vt_ipaddress(self, ip) -> dict:
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

    def parse_summary_ipaddress(self, res) -> dict:
        """ """
        print(res)
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

    def parse_comments_of_ipaddress(self, res) -> dict:     
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

    def get_vt_domain(self, domain) -> dict:
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
    
    def parse_summary_domain(self, res) -> dict:
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

    def fetch_unknown_vtrisk(self):
        not_yet_investgated = DataList.objects.filter(malicious_level=0)
        print(not_yet_investgated)
        for target in not_yet_investgated:
            vt_result = self.fetch_vt_risk(target.data_id)
            print(target, vt_result)
            target_data = DataList.objects.get(data_id=target)
            target_data.analyzing_type = vt_result['type']
            target_data.gui_url = vt_result['gui']
            target_data.last_analyzed = timezone.now()
            target_data.malicious_level = vt_result['malicious_level']
            target_data.save()
            vt_osint = VtSummary(osint_id=target_data, owner=vt_result['owner'], 
                                gui_url=vt_result['gui'],
                                malicious_level=vt_result['malicious_level'],)
            vt_osint.save()

    def update_vtrisk(self):
        all_osints = DataList.objects.all()
        for osint in all_osints:
            vt_result = self.fetch_vt_risk(osint.data_id)
            print(osint, vt_result)
            osint_data = DataList.objects.get(data_id=osint.data_id)
            vt_osint = VtSummary(osint_id=osint_data, owner=vt_result['owner'], 
                                gui_url=vt_result['gui'],
                                malicious_level=vt_result['malicious_level'],)
            vt_osint.save()
            time.sleep(15)
        for row in DataList.objects.all().reverse():
            if DataList.objects.filter(data_id=row.data_id).count() > 1:
                row.delete()


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
        if response['results']:
            result = []
            for res in response['results']:
                result.append(self.parse_domain_detail(res))
            return result
        else:
            return {'result': 'This IoC is not in UrlScan'}
    
    def parse_domain_detail(self, res) -> dict:
        page = res['page']
        indexedAt = re.sub('\.\d*\.*Z', '', res['indexedAt'])
        ip = page['ip'] if 'ip' in page else None
        domain = page['domain'] if 'domain' in page else None
        server = page['server'] if 'server' in page else None
        asnname = page['asnname'] if 'asnname' in page else None
        asn = page['asn'] if 'asn' in page else None
        ptr = page['ptr'] if 'ptr' in page else None
        screenshot = res['screenshot'] if 'screenshot' in res else None
        parsed_result = {'date': datetime.fromisoformat(indexedAt), 
                        'ipaddress': ip, 'domain': domain, 'server': server,
                        'asnname': asnname, 'asn': asn, 'ptr': ptr,
                        'screenshot': screenshot}
        return parsed_result

    def save_osint_info(self, target_osint) -> None:
        us_results = self.fetch_domain_detail(target_osint)
        osint_id = DataList.objects.get(data_id=target_osint)
        for us_result in us_results:
            us_osint = UrlScan(osint_id=osint_id, date=us_result['date'],
                domain=us_result['domain'], server=us_result['server'], 
                primary_ip=us_result['ipaddress'],asnname=us_result['asnname'], 
                asn=us_result['asn'], ptr=us_result['ptr'], 
                screenshot=us_result['screenshot'])
            try:
                us_osint.save()
            except IntegrityError:
                pass