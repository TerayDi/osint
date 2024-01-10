import requests, json, configparser

class VT(object):
    def __init__(self):
        config = configparser.ConfigParser()
        config.read(r"api.conf")
        self.__KEY= config.get('VirusTotal','key')
        self.__URL="https://www.virustotal.com/api/v3/"

    def __enter__(self):
        return self
    
    def __exit__(self, ext_type, exc_value, traceback):
        del self
   
    #Public methods
    def send_req(self, **kwargs) -> str|dict:
        headers = {
                'Accept': 'application/json',
                'x-apikey': self.__KEY
                }
        if kwargs.get('ip'):
            __ip = kwargs.get('ip')
            url = self.__URL + "/ip_addresses/" + __ip
            response =  requests.request(method='GET', url=url, headers=headers)
            return self.ip_request(response=response, ip=__ip)
        if kwargs.get('domain'):
            __domain = kwargs.get('domain')
            url = self.__URL + "/domains/" + __domain
            response =  requests.request(method='GET', url=url, headers=headers)
            return self.domain_request(response=response, domain=__domain)
        if kwargs.get('hash'):
            __hash= kwargs.get('hash')
            __filename = kwargs.get('filename') if kwargs.get('fielname') else None
            url = self.__URL + "/files/" + __hash
            response = requests.request(method="GET", url=url, headers=headers)
            return self.hash_request(response=response, hash=__hash, filename=__filename)

    def ip_request(self, **kwargs) -> dict | str:
        if "error" not in kwargs.get('response'):
            response = json.loads(kwargs.get('response').text)
            values = response['data']['attributes']["last_analysis_stats"].values()
            total_stats = sum(values)

            __data = {'IP': kwargs.get('ip'),
                    'Owner': response['data']['attributes']['as_owner'],
                    #'CN': response['data']['attributes']['last_https_certificate']['subject']['CN'],
                    'Total Engine': total_stats,
                    'Malicious':f'{response["data"]["attributes"]["last_analysis_stats"]["malicious"]}/{total_stats}',
                    'Suspicious':f'{response["data"]["attributes"]["last_analysis_stats"]["suspicious"]}/{total_stats}',
                    'Harmless': f'{response["data"]["attributes"]["last_analysis_stats"]["harmless"]}/{total_stats}',
                    'Undetected':f'{response["data"]["attributes"]["last_analysis_stats"]["undetected"]}/{total_stats}',
                    'Timeout': f'{response["data"]["attributes"]["last_analysis_stats"]["timeout"]}/{total_stats}'
                    }
            if len(__data) > 0:
                return __data
            else:
                return "No data returned from VirusTotal"
            
    def domain_request(self, **kwargs) -> dict | str:
        if "error" not in kwargs.get('response'):
            response = json.loads(kwargs.get('response').text)
            values = response['data']['attributes']["last_analysis_stats"].values()
            total_stats = sum(values)
            #after
            cat = [category for category in response['data']['attributes']['categories'].values() if any (category in subcategory or subcategory in category for subcategory in response['data']['attributes']['categories'].values())]
            categories = ", ".join(cat) if len(cat) > 1 else "".join(cat)
            #end after
            __data = {'CN': response['data']['attributes']['last_https_certificate']['subject']['CN'],
                    #'Categories': response['data']['attributes']['categories'], ->before
                    'Categories': categories,
                    'Total Engine': total_stats,
                    'Malicious':f'{response["data"]["attributes"]["last_analysis_stats"]["malicious"]}/{total_stats}',
                    'Suspicious':f'{response["data"]["attributes"]["last_analysis_stats"]["suspicious"]}/{total_stats}',
                    'Harmless': f'{response["data"]["attributes"]["last_analysis_stats"]["harmless"]}/{total_stats}',
                    'Undetected':f'{response["data"]["attributes"]["last_analysis_stats"]["undetected"]}/{total_stats}',
                    'Timeout': f'{response["data"]["attributes"]["last_analysis_stats"]["timeout"]}/{total_stats}'
                    #'Whois results': '\n'+response['data']['attributes']['whois']
                    }
            if len(__data) > 0:
                return __data
            else:
                return "No data returned from VirusTotal"
            
    def hash_request(self, **kwargs) -> dict | str:
        if "error" not in kwargs.get('response'):
            response = json.loads(kwargs.get('response').text)
            values = response['data']['attributes']["last_analysis_stats"].values()
            total_stats = sum(values)
            if kwargs.get('filename') is not None:
                _filename = kwargs.get('filename')
            else:
                _filename = response['data']['attributes']['meaningful_name'] if response['data']['attributes']['meaningful_name'] else "N\A" 
            if len(kwargs.get("hash")) == 64 :
                hash_type = "SHA256"
            elif len(kwargs.get("hash")) == 40:
                hash_type = "SHA1"
            elif len(kwargs.get("hash")) == 32:
                hash_type = "MD5"
            else:
                hash_type = "N\A"
            __data = {'File': _filename,
                    'Hash':kwargs.get('hash'),
                    "Hash type":hash_type,
                    'Total Engine': total_stats,
                    'Malicious':f'{response["data"]["attributes"]["last_analysis_stats"]["malicious"]}/{total_stats}',
                    'Suspicious':f'{response["data"]["attributes"]["last_analysis_stats"]["suspicious"]}/{total_stats}',
                    'Harmless': f'{response["data"]["attributes"]["last_analysis_stats"]["harmless"]}/{total_stats}',
                    'Undetected':f'{response["data"]["attributes"]["last_analysis_stats"]["undetected"]}/{total_stats}',
                    'Type Unsupported':f'{response["data"]["attributes"]["last_analysis_stats"]["type-unsupported"]}/{total_stats}',
                    'Timeout': f'{response["data"]["attributes"]["last_analysis_stats"]["timeout"]}/{total_stats}'
                    #'Whois results': '\n'+response['data']['attributes']['whois']
                    }
            if len(__data) > 0:
                return __data
            else:
                return "No data returned from VirusTotal"