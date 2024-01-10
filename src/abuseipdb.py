#import ipaddress
import requests, json, configparser

class Abuse(object):
    def __init__(self):
        config = configparser.ConfigParser()
        config.read(r"api.conf")
        self.__KEY= config.get('AbuseIPDB','key')
        self.__URL= "https://api.abuseipdb.com/api/v2/check/"

    def __enter__(self):
        return self
    
    def __exit__(self, ext_type, exc_value, traceback):
        del self
   
    #Public methods
    def send_req(self, **kwargs) -> str|dict:
        __ip = kwargs.get('ip')
        headers = {
            'Accept': 'application/json',
            'Key': self.__KEY
            }
        querystring = { 
            'ipAddress': __ip,
            'verbose':''
            }
        response =  requests.request(method='GET', url=self.__URL, headers=headers, params=querystring)
        if "error" not in response:
            response = json.loads(response.text)
            __data = {'IP':kwargs.get('ip'),
                    'ISP':response['data']['isp'],
                    'Domain':response['data']['domain'],
                    'Usage':response['data']['usageType'], 
                    'Confidence':f'{response["data"]["abuseConfidenceScore"]}%',
                    'Categories':', '.join(self.__get_categories(response))
                    }
            if len(__data) > 0:
                return __data
            else:
                return "No data returned from AbuseIPDB"

    #Private methods
    def __get_categories(self, response) -> list:
        tmp_catergory = []
        if response['data']['totalReports'] > 0:
            for report in response['data']['reports']:
                category = report['categories']
                for cat in category:
                    if (self.__get_cat(cat) not in tmp_catergory):
                        tmp_catergory.append(self.__get_cat(cat))
        return tmp_catergory

    def __get_cat(self, cat) -> str:
        return {
            0: 'BLANK',
            1:'DNS Compromise',
            2:'DNS Poisoning',
            3: 'Fraud_Orders',
            4: 'DDoS_Attack',
            5: 'FTP_Brute-Force',
            6: 'Ping of Death',
            7: 'Phishing',
            8: 'Fraud VoIP',
            9: 'Open_Proxy',
            10: 'Web_Spam',
            11: 'Email_Spam',
            12: 'Blog_Spam',
            13: 'VPN IP',
            14: 'Port_Scan',
            15: 'Hacking',
            16: 'SQL Injection',
            17: 'Spoofing',
            18: 'Brute_Force',
            19: 'Bad_Web_Bot',
            20: 'Exploited_Host',
            21: 'Web_App_Attack',
            22: 'SSH',
            23: 'IoT_Targeted'
        }.get(
            cat,
            'UNK CAT;***REPORT TO MAINTAINER***OPEN AN ISSUE ON GITHUB w/ IP***')