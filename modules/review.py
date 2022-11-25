#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This class accepts a list of domains from a provided Django query set and then
reviews each one to ensure it is ready to be used for an op. This involves checking to see if
the domain is properly categorized, the domain has not been flagged in VirusTotal or tagged
with a bad category, and the domain is not blacklisted for spam.

DomainReview checks the domain against VirusTotal, Cisco Talos, Bluecoat, IBM X-Force, Fortiguard, 
TrendMicro, OpeDNS, and MXToolbox. Domains will also be checked against malwaredomains.com's list
of reported domains.
"""

import os
import re
import csv
import sys
import json
import shutil
import base64
from time import sleep

from django.conf import settings
from catalog.models import Domain

import requests
import pytesseract
from PIL import Image
from lxml import etree
from lxml import objectify
from cymon import Cymon
from bs4 import BeautifulSoup


# Disable requests warnings for things like disabling certificate checking
requests.packages.urllib3.disable_warnings()


class DomainReview(object):
    """Class to pull a list of registered domains belonging to a Namecheap account and then check
    the web reputation of each domain.
    """
    # API endpoints
    malwaredomains_url = 'http://mirror1.malwaredomains.com/files/justdomains'
    virustotal_domain_report_uri = 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}'
    # Categories we don't want to see
    # These are lowercase to avoid inconsistencies with how each service might return the categories
    blacklisted = ['phishing', 'web ads/analytics', 'suspicious', 'shopping', 'placeholders', 
                   'pornography', 'spam', 'gambling', 'scam/questionable/illegal', 
                   'malicious sources/malnets']
    # Variables for web browsing
    useragent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'
    session = requests.Session()

    def __init__(self, domain_queryset):
        """Everything that needs to be setup when a new DomainReview object is created goes here."""
        # Domain query results from the Django models
        self.domain_queryset = domain_queryset
        # Try to get the sleep time configured in settings
        try:
            self.request_delay = settings.DOMAINCHECK_CONFIG['sleep_time']
        except Exception as error:
            self.request_delay = 20
        try:
            self.virustotal_api_key = settings.DOMAINCHECK_CONFIG['virustotal_api_key']
        except Exception as error:
            self.virustotal_api_key = None
            print('[!] A VirusTotal API key could not be pulled from settings.py. Review settings to perform VirusTotal checks.')
            exit()

    def check_virustotal(self, domain, ignore_case=False):
        """Check the provided domain name with VirusTotal. VirusTotal's API is case sensitive, so
        the domain will be converted to lowercase by default. This can be disabled using the
        ignore_case parameter.

        This uses the VirusTotal /domain/report endpoint:

        https://developers.virustotal.com/v2.0/reference#domain-report
        """
        if self.virustotal_api_key:
            if not ignore_case:
                domain = domain.lower()
            try:
                req = self.session.get(self.virustotal_domain_report_uri.format(self.virustotal_api_key, domain))
                vt_data = req.json()
            except:
                vt_data = None
            return vt_data
        else:
            return None

    def check_talos(self, domain):
        """Check the provided domain's category as determined by Cisco Talos."""
        categories = []
        cisco_talos_uri = 'https://www.talosintelligence.com/cloud_intel/url_reputation?'
        PARAMS = {'url':domain}
        #cisco_talos_uri = 'https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={}&offset=0&order=ip+asc'
        headers = {'User-Agent': self.useragent, 
                   'Referer': 'https://www.talosintelligence.com/reputation_center/lookup?search=' + domain}
        try:
            req = self.session.get(cisco_talos_uri.format(domain), params = PARAMS, headers=headers)
            #r = requests.get(url = URL, params = PARAMS)
            #print(req)
            if req.ok:
                json_data = req.json()
                #print(json_data)
                category = json_data['reputation']
                if category:
                    try:
                        categories.append(json_data['reputation']['aup_cat'][0]['desc_short'][0]['text'])
                    #print(json_data['reputation']['aup_cat'][0]['desc_short'][0]['text'])
                    #print("End.\n")
                    except IndexError:
                        categories.append('Uncategorized')  
                else:
                    categories.append('Uncategorized')
            else:
                print('[!] Cisco Talos check request failed. Talos did not return a 200 response.')
                print('L.. Request returned status "{}"'.format(req.status_code))
        except Exception as error:
                print('[!] Cisco Talos request failed: {}'.format(error))
        return categories

    def check_ibm_xforce(self, domain):
        """Check the provided domain's category as determined by IBM X-Force."""
        categories = []
        xforce_uri = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent': self.useragent, 
                   'Accept': 'application/json, text/plain, */*', 
                   'x-ui': 'XFE', 
                   'Origin': xforce_uri, 
                   'Referer': xforce_uri}
        xforce_api_uri = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
        try:
            req = self.session.get(xforce_api_uri, headers=headers, verify=False)
            if req.ok:
                response = req.json()
                if not response['result']['cats']:
                    categories.append('Uncategorized')
                else:
                    temp = ''
                    # Parse all dictionary keys and append to single string to get Category names
                    for key in response['result']['cats']:
                        categories.append(key)
            # IBM X-Force returns a 404 with {"error":"Not found."} if the domain is unknown
            elif req.status_code == 404:
                categories.append('Unknown')
            else:
                print('[!] IBM X-Force check request failed. X-Force did not return a 200 response.')
                print('L.. Request returned status "{}"'.format(req.status_code))
        except Exception as error:
            print('[!] IBM X-Force request failed: {}'.format(error))
        return categories

    def check_fortiguard(self, domain):
        """Check the provided domain's category as determined by Fortiguard Webfilter."""
        categories = []
        fortiguard_uri = 'https://fortiguard.com/webfilter?q=' + domain
        headers = {'User-Agent': self.useragent, 
                   'Origin': 'https://fortiguard.com', 
                   'Referer': 'https://fortiguard.com/webfilter'}
        try:
            req = self.session.get(fortiguard_uri, headers=headers)
            if req.ok:
                """
                Example HTML result:
                <div class="well">
                    <div class="row">
                        <div class="col-md-9 col-sm-12">
                            <h4 class="info_title">Category: Education</h4>
                """
                # TODO: Might be best to BS4 for this rather than regex
                cat = re.findall('Category: (.*?)" />', req.text, re.DOTALL)
                categories.append(cat[0])
            else:
                print('[!] Fortiguard check request failed. Fortiguard did not return a 200 response.')
                print('L.. Request returned status "{}"'.format(req.status_code))
        except Exception as error:
            print('[!] Fortiguard request failed: {}'.format(error))
        return categories

    def check_barracuda(self, domain):
        """Check the provided domain's category as determined by BarracudaCentral."""
        #https://www.barracudacentral.org/lookups/lookup-reputation?lookup_entry=cdn-emea.com&submit=Check+Reputation
        categories = []
        barracuda_uri = 'https://www.barracudacentral.org/lookups/lookup-reputation?' + domain
        PARAMS = {'lookup_entry':domain, 'submit':'Check+Reputation'}
        headers = {'User-Agent':self.useragent}
        try:
            req = self.session.get(barracuda_uri, params=PARAMS, headers=headers)
            if req.ok:
                # TODO: Might be best to BS4 for this rather than regex, it's a of a rogue way of finding the category from an HTML dump...
                res = re.findall("<strong>(.*?)</strong>", req.text)
                try:
                    categories.append(res[2])
                except IndexError:
                    categories.append('Uncategorised')
            else:
                print('[!] Barracuda check request failed. Barracuda did not return a 200 response.')
                print('L.. Request returned status "{}"'.format(req.status_code))
        except Exception as error:
            print('[!] Barracuda request failed: {}'.format(error))
        return categories

    def check_opendns(self, domain):
        """Check the provided domain's category as determined by the OpenDNS community."""
        categories = []
        opendns_uri = 'https://domain.opendns.com/{}'
        headers = {'User-Agent':self.useragent}
        try:
            response = self.session.get(opendns_uri.format(domain), headers=headers, verify=False)
            soup = BeautifulSoup(response.content, 'lxml')
            tags = soup.find('span', {'class': 'normal'})
            if tags:
                categories = tags.text.strip().split(', ')
            else:
                categories.append('No Tags')
        except Exception as error:
            print('[!] OpenDNS request failed: {0}'.format(error))
        return categories

    def check_trendmicro(self, domain):
        """Check the provided domain's category as determined by the Trend Micro."""
        categories = []
        trendmicro_uri = 'https://global.sitesafety.trendmicro.com/'
        trendmicro_stage_1_uri = 'https://global.sitesafety.trendmicro.com/lib/idn.php'
        trendmicro_stage_2_uri = 'https://global.sitesafety.trendmicro.com/result.php'
        headers = {'User-Agent': self.useragent}
        headers_stage_1 = {
                           'Host': 'global.sitesafety.trendmicro.com', 
                           'Accept': '*/*', 
                           'Origin': 'https://global.sitesafety.trendmicro.com', 
                           'X-Requested-With': 'XMLHttpRequest', 
                           'User-Agent': self.useragent, 
                           'Content-Type': 'application/x-www-form-urlencoded', 
                           'Referer': 'https://global.sitesafety.trendmicro.com/index.php', 
                           'Accept-Encoding': 'gzip, deflate', 
                           'Accept-Language': 'en-US, en;q=0.9'
                          }
        headers_stage_2 = {
                           'Origin': 'https://global.sitesafety.trendmicro.com', 
                           'Content-Type': 'application/x-www-form-urlencoded', 
                           'User-Agent': self.useragent, 
                           'Accept': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, image/apng, */*;q=0.8', 
                           'Referer': 'https://global.sitesafety.trendmicro.com/index.php', 
                           'Accept-Encoding': 'gzip, deflate', 
                           'Accept-Language': 'en-US, en;q=0.9'
                          }
        data_stage_1 = {'url': domain}
        data_stage_2 = {'urlname': domain, 
                        'getinfo': 'Check Now'
                       }
        try:
            response = self.session.get(trendmicro_uri, headers=headers)
            response = self.session.post(trendmicro_stage_1_uri, headers=headers_stage_1, data=data_stage_1)
            response = self.session.post(trendmicro_stage_2_uri, headers=headers_stage_2, data=data_stage_2)
            # Check if session was redirected to /captcha.php
            if 'captcha' in response.url:
                print('[!] TrendMicro responded with a reCAPTCHA, so cannot proceed with TrendMicro.')
                print('L.. You can try solving it yourself: https://global.sitesafety.trendmicro.com/captcha.php')
            else:
                soup = BeautifulSoup(response.content, 'lxml')
                tags = soup.find('div', {'class': 'labeltitlesmallresult'})
                if tags:
                    categories = tags.text.strip().split(', ')
                else:
                    categories.append('Uncategorized')
        except Exception as error:
            print('[!] Trend Micro request failed: {0}'.format(error))
        return categories

    def check_vtip(self, target):
        url = "https://www.virustotal.com/api/v3/ip_addresses/"+ target
        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_api_key
        }
        try:
            response = requests.get(url, headers=headers)
            attributes = response.json()
            results = attributes['data']['attributes']['last_analysis_results']
        except Exception as error:
            print("[!] VT IP address reputation check failed: {0}".format(error)) 
        return results
        
    def check_domain_status(self):
        """Check the status of each domain in the provided list collected from the Domain model.
        Each domain will be checked to ensure the domain is not flagged/blacklisted. A domain
        will be considered burned if VirusTotal returns detections for the domain or one of the
        domain's categories appears in the list of bad categories.

        VirusTotal allows 4 requests every 1 minute. A minimum of 20 seconds is recommended to
        allow for some consideration on the service.

        """
        lab_results = {}
        for domain in self.domain_queryset:
            print('[+] Starting update of {}'.format(domain.name))
            burned_dns = False
            domain_categories = []
            # Sort the domain information from queryset
            domain_name = domain.name
            health = domain.health_status
            # Check if domain is known to be burned and skip it if so
            # This just saves time and operators can edit a domain and set status to `Healthy` as needed
            # The domain will be included in the next update after the edit
            if health != 'Healthy':
                burned = False
            else:
                burned = True
            if not burned:
                burned_explanations = []
                # Check domain name with VirusTotal
                vt_results = self.check_virustotal(domain_name)
                if 'categories' in vt_results:
                    domain_categories = vt_results['categories']
                # Check if VirusTotal has any detections for URLs or samples
                if 'detected_downloaded_samples' in vt_results:
                    if len(vt_results['detected_downloaded_samples']) > 0:
                        print('[!] {}: Identified as having a downloaded sample on VirusTotal!'.format(domain_name))
                        burned = True
                        burned_explanations.append('Tied to a VirusTotal detected malware sample')
                if 'detected_urls' in vt_results:
                    if len(vt_results['detected_urls']) > 0:
                        print('[!] {}: Identified as having a URL detection on VirusTotal!'.format(domain_name))
                        burned = True
                        burned_explanations.append('Tied to a VirusTotal detected URL')
                # Get passive DNS results from VirusTotal JSON
                ip_addresses = []
                if 'resolutions' in vt_results:
                    for address in vt_results['resolutions']:
                        ip_addresses.append({'address':address['ip_address'], 'timestamp':address['last_resolved'].split(' ')[0]})
                bad_addresses = []
                for address in ip_addresses:
                    ip = address['address']
                    vtip_results = DomainReview.check_vtip(ip)
                    for key, subkey in vtip_results.items():
                        if subkey['category'] == "malicious":
                            burned_dns = True
                            bad_addresses.append(address['address'] + '/' + address['timestamp'])
                if burned_dns:
                    print('[*] {}: Identified as pointing to suspect IP addresses (VirusTotal passive DNS).'.format(domain_name))
                    health_dns = 'Flagged DNS ({})'.format(', '.join(bad_addresses))
                else:
                    health_dns = "Healthy"
                # Collect categories from the other sources
                xforce_results = self.check_ibm_xforce(domain_name)
                domain_categories.extend(xforce_results)
                talos_results = self.check_talos(domain_name)
                domain_categories.extend(talos_results)
                barracuda_results = self.check_barracuda(domain_name)
                domain_categories.extend(barracuda_results)
                fortiguard_results = self.check_fortiguard(domain_name)
                domain_categories.extend(fortiguard_results)
                opendns_results = self.check_opendns(domain_name)
                domain_categories.extend(opendns_results)
                trendmicro_results = self.check_trendmicro(domain_name)
                domain_categories.extend(trendmicro_results)
                # Make categories unique
                domain_categories = list(set(domain_categories))
                # Check if any categories are suspect
                bad_categories = []
                for category in domain_categories:
                    if category.lower() in self.blacklisted:
                        bad_categories.append(category.capitalize())
                if bad_categories:
                    burned = True
                    burned_explanations.append('Tagged with a bad category')
                # Assemble the dictionary to return for this domain
                lab_results[domain] = {}
                lab_results[domain]['categories'] = {}
                lab_results[domain]['burned'] = burned
                lab_results[domain]['burned_explanation'] = ', '.join(burned_explanations)
                lab_results[domain]['health_dns'] = health_dns
                lab_results[domain]['categories']['all'] = ', '.join(bad_categories)
                lab_results[domain]['categories']['bad'] = ', '.join(domain_categories)
                lab_results[domain]['categories']['talos'] = ', '.join(talos_results)
                lab_results[domain]['categories']['xforce'] = ', '.join(xforce_results)
                lab_results[domain]['categories']['opendns'] = ', '.join(opendns_results)
                lab_results[domain]['categories']['barracuda'] = ', '.join(barracuda_results)
                lab_results[domain]['categories']['fortiguard'] = ', '.join(fortiguard_results)
                lab_results[domain]['categories']['trendmicro'] = ', '.join(trendmicro_results)
                # Sleep for a while for VirusTotal's API
                sleep(self.request_delay)
        return lab_results
