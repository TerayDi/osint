import argparse, ipaddress, socket, pathlib, os
import email_parser, mapi
from abuseipdb import Abuse
from vt import VT

def art():
    art=f'''
 _____ _____ _____ _   _ _____    ___  ____________ 
|  _  /  ___|_   _| \ | |_   _|  / _ \ | ___ \ ___ \\
| | | \ `--.  | | |  \| | | |   / /_\ \| |_/ / |_/ /
| | | |`--. \ | | | . ` | | |   |  _  ||  __/|  __/ 
\ \_/ /\__/ /_| |_| |\  | | |   | | | || |   | |    
 \___/\____/ \___/\_| \_/ \_/   \_| |_/\_|   \_|   
'''
    print(art + "\tby teraydi, kublai\n")

#NSLookup tool    
def get_hostname(address:str) -> None:
    if address.replace('.', '').isnumeric():
        name = socket.getfqdn(address)
        value = f'IP Address: {address}\nName: {name}'
    else:
        ip = socket.gethostbyname(address)
        value = f'Name: {address}\nIP Address: {ip}'
    print("nslookup tool results")
    print("---------------------------------------------------------------")
    print(value)
    print("---------------------------------------------------------------")

#email_parser.py
def email(file_path:str) -> str | None:
    try:
        path_to_file = pathlib.Path(file_path)
        filename = path_to_file.name
        if  filename.split(".")[1] == "msg":
            parser = email_parser.MsgParser(path_to_file)
            header_mail = parser.get_info_header()
            filenames = (", ".join(parser.get_attachments_names()) if isinstance(parser.get_attachments_names(), list) else parser.get_attachments_names())
            hash_filenames = parser.calculate_hash()
            enable_save = True if isinstance(parser.get_attachments_names(), list) else False
            header_mail["attachments"] = filenames
            header_mail['hashs'] = hash_filenames
        
        elif filename.split(".")[1] == "eml":
            parser = email_parser.EmlParser(path_to_file)
            header_mail = parser.get_header_info()
            filenames = (", ".join(parser.get_attachments_names()) if isinstance(parser.get_attachments_names(), list) else parser.get_attachments_names())
            enable_save = True if isinstance(parser.get_attachments_names(), list) else False
            hash_filenames = parser.calculate_hash()
            header_mail["attachments"] = filenames
            header_mail['hashs'] = hash_filenames
    
        else:
            header_mail = email_parser.dict_mapped(file_path) #dizionario con i campi
    except FileNotFoundError:
        return "Error, File not found.\nPlease insert a right path to file."
    
    print("Parsing results")
    print(f'\nFilename: {filename}')
    print("---------------------------------------------------------------")    
    if "from" in header_mail.keys():
        print(f'From: {header_mail.get("from")}')
        print("---------------------------------------------------------------")
    if "to" in header_mail.keys():
        print(f'To: {header_mail.get("to")}')
        print("---------------------------------------------------------------")                
    if "subject" in header_mail.keys():
        print(f'Subject: {header_mail.get("subject")}')
        print("---------------------------------------------------------------")
    if "sender_ip" in header_mail.keys():
        for ip in header_mail.get("sender_ip"):
            print(f"External IP: {ip}")
            print("---------------------------------------------------------------")
    print("DMARC result: N\A\n---------------------------------------------------------------") if "dmarc" not in header_mail.keys() else print(f'DMARC result: {header_mail.get("dmarc")}' + "\n---------------------------------------------------------------")
    print("DKIM result: N\A\n---------------------------------------------------------------") if "dkim" not in header_mail.keys() else print(f'DKIM result: {header_mail.get("dkim")}' + "\n---------------------------------------------------------------")
    print("SPF result: N\A\n---------------------------------------------------------------") if "spf" not in header_mail.keys() else print(f'SPF result: {header_mail.get("spf")}' + "\n---------------------------------------------------------------") 
    if "urls" in header_mail.keys():
        print("URLs entries:\n")
        index = 0
        trusted_index = 0
        trusted_domains = ["microsoft.com", "w3.org", "openxmlformats.org", "xmlsoap.org"]
        print("Unknown urls:")
        trusted_urls = [url for url in header_mail.get("urls") if any (url in domain or domain in url for domain in trusted_domains)]
        for url in header_mail.get("urls"):
            if url not in trusted_urls:
                index+=1
                print(f'{str(index)}: {url}')  
        print("---------------------------------------------------------------")
        print("Trusted urls:")
        
        for url in trusted_urls:
            trusted_index +=1
            print(f'{str(trusted_index)}: {url}')
        print("---------------------------------------------------------------")

    else:
        print("URLs entries: URLs not found")
        print("---------------------------------------------------------------")
    if "attachments" in header_mail.keys():
        print(f'Attachments: {header_mail.get("attachments")}')
        print("---------------------------------------------------------------")
        if "hashs" in header_mail.keys():
            print(f'Attachments hash:')
            dim = 0
            for key in header_mail['hashs'].keys():
                dim = len(str(key)) if len(str(key)) > dim else dim
            print('Filename'.ljust(dim,' ') + 'SHA256'.rjust(13," "))
            for key, value in header_mail['hashs'].items():
                output = str(key).ljust(dim, ' ') + '  -->  '+ str(value)
                print(output)
            print("---------------------------------------------------------------")
        if enable_save:
            current_path= os.getcwd()
            choice = input("Do you want save one file?(y/n): ") 
            if (choice== "y") or (choice== "yes"):
                filename = input("What file do you want save?\n")
                path = input(f"Where do you want save it?\n(default: <{current_path}>): ")
                status = parser.save_attachment(filename) if len(path) < 1 else parser.save_attachment(filename, path=path)
            elif (choice =="no") or (choice == "n"):
                status = "Save skipped"
            else:
                status = f'"{choice}" is not valid choice\nSave skipped'
            print(status)

#check with abuseipdb.py and vt.py using api     
def ip_check(ip:str) -> None:
    print("IP Reputation Check results")
    print("---------------------------------------------------------------")
    if not ip.replace(".","").isnumeric():
        print(f'Value "{ip}" is not a valid IP')
        return
    try:
        private_ip = ipaddress.ip_address(ip).is_private
        value = "Private" if private_ip else "Public"
        if not private_ip:
            print("AbuseIPDB results:")
            with Abuse() as ab:
                rep = ab.send_req(ip=ip)
                for key, value in rep.items():
                    output=str(key).ljust(15,' ') + str(value)
                    print(output)
            print("---------------------------------------------------------------")
            print("VirusTotal results:")
            with VT() as vt:
                rep = vt.send_req(ip=ip)
                for key, value in rep.items():
                    output= str(key).ljust(15,' ') + str(value)
                    print(output)
        elif private_ip:
            print(f'IP "{ip}" is {value}')
        print("---------------------------------------------------------------")
    except ValueError:
        print(f'Invalid IP address: "{ip}"')
        print("---------------------------------------------------------------")


def check_domain(domain:str):
    print("Domain reputation results")
    print("---------------------------------------------------------------")
    print(f'Domain {domain}')
    print("---------------------------------------------------------------")
    print("VirusTotal results:")
    with VT() as vt:
        rep=vt.send_req(domain=domain)
        for key, value in rep.items():
            output = str(key).ljust(15,' ') + str(value)
            print(output)
    print("---------------------------------------------------------------")


def check_hash(var:str):
    print("Hash reputation results")
    print("---------------------------------------------------------------")
    print("VirusTotal results")
    with VT() as vt:
        rep = vt.send_req(hash=var)
        for key, value in rep.items():
            output= str(key).ljust(20,' ') + str(value)
            print(output)

    print("---------------------------------------------------------------")

def check_api_conf():
    mapi.check_api()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=art())
    parser.add_argument("-c", "--check", metavar='<ip-address>', type=ip_check, help="Check IP reputation")
    parser.add_argument("-e", metavar='<mail-path>', help="Parsing email tool", type=email)
    parser.add_argument("-n", "--nslookup", metavar="<ip-address | domain>", type=get_hostname, help="NSLookup tool")
    parser.add_argument("-d","--domain", metavar="<domain>", type=check_domain, help="Check domain reputation")
    parser.add_argument("-t", metavar="<hash>", type=check_hash, help="Check file hash reputation" )
    parser.add_argument("-mapi", action="store_const", const=check_api_conf, help="Check API config")
    args = parser.parse_args()
    if args.mapi:
        args.mapi()