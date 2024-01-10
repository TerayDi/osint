import re, ipaddress, extract_msg, os, email, hashlib
from email.policy import default

info = {}
file_path= ""

def dict_mapped(file_path):
    external_ip = []
    urls = []
    line_index=0
    with open(file_path, "r") as file:
        content = file.read() #tutto il file
        list_lines= content.splitlines() #lista con elementi =  righe elemnto in posizione 0 = linea 1 del file
        for line in list_lines:
            line_index +=1
            if re.search(r"^From: ", line):
                #sender = line.split("<")[1].split(">")[0]
                sender= re.findall(r'(([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+)', line)[0][0]
                info["from"] = str(sender)
                #print(sender)
            if re.search(r"^To: ", line):
                recipient = re.findall(r'(([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+)', line)[0][0]
                #print(recipient)
                info["to"] = str(recipient)
                #print(recipient)
            if re.search(r"^Subject: ", line):
                subject = line.split("Subject: ")[1].replace("\n", "")
                info["subject"] = str(subject)
                #print(subject)
            if re.search(r"spf=(.*?)\s", line):
                spf= re.findall(r'^.*spf=(\w+)',line.lower())[0]
                #print(spf)
                if spf not in info:
                    info["spf"] = spf
            if re.search(r"dmarc=(.*?)\s", line):
                dmarc = re.findall(r'^.*dmarc=(\w+)',line.lower())[0]
                if dmarc not in info:
                    info["dmarc"] = dmarc
            if re.search(r"dkim=(.*?)\s", line):
                dkim= re.findall(r'^.*dkim=(\w+)',line.lower())[0]
                if dkim not in info:
                    info["dkim"] = dkim  
            if re.search(r'(?<![.\d])\b\d{1,3}(?:\.\d{1,3}){3}\b(?![.\d])', line):
                sender_ip= re.findall(r'(?<![.\d])\b\d{1,3}(?:\.\d{1,3}){3}\b(?![.\d])', line)[0]
                if ipaddress.ip_address(sender_ip).is_private:
                    pass
                else:
                    if sender_ip not in external_ip:
                        external_ip.append(sender_ip)
                info["sender_ip"] = external_ip
            if re.search('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', line):
                initial_url =  re.findall('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', line)[0][0]
                url = search_url_helper(initial_url, list_lines, line_index)  
                if url not in urls:
                    urls.append(url)
                else:
                    pass
                info["urls"] = urls             
    return info

def search_url_helper(initial_url,list_lines, index_line):
    # Check if the URL continues on the next line
    if ('"' in initial_url) or ("'" in initial_url):
        url = re.match(r'([^\'|\"]+)[\'\"\]]', initial_url)
        if url:
            final_url = url.group(1)
            return final_url
    if "=" in initial_url[len(initial_url)-1]:
        url = initial_url[:-1] + list_lines[index_line]
        return search_url_helper(url, list_lines, index_line+1)
    return initial_url

class MsgParser:
    def __init__(self, email) -> None:
        self.filenames = []
        self.hash_files = {}
        self.file_path = email
        self.msg = extract_msg.Message(email)

    def attachments(self) -> list:
        return self.msg.attachments
    
    #def get_info_header(self) -> dict:
    #    return dict_mapped(self.msg.header)
    
    #---> create tmp file to save header and after dict_mapped() method was called, it is deleted
    def get_info_header(self) -> dict:
        with open("tmp.txt","w") as f:
            f.write(str(self.msg.header))
        info = dict_mapped(str(os.getcwd()) + "\\tmp.txt")
        os.remove("tmp.txt")
        return info
    
    def get_attachments_names(self) -> str|list:
        if len(self.msg.attachments) < 1:
            return "No attachments found"
        for file in self.msg.attachments:
            if file.longFilename not in self.filenames:
                self.filenames.append(file.longFilename)
        return self.filenames
    
    def calculate_hash(self) -> dict:
        for file in self.msg.attachments:
            data = file.data
            if file.longFilename not in self.hash_files.keys():
                sha256 = hashlib.sha256()
                sha256.update(data)
                self.hash_files[file.longFilename] = sha256.hexdigest()
        return self.hash_files

    def save_attachment(self, attachment_name:str, **kwargs) -> str:
        self.filenames = [x.lower() for x in self.filenames]
        if attachment_name.lower() in self.filenames: 
            index=self.filenames.index(attachment_name.lower())
            if "path" in kwargs.keys():
                path= kwargs["path"]
                try:
                    self.msg.attachments[index].save(customPath= path)
                except FileNotFoundError:
                    return f'Directory "{path}" not found\nSave skipped'
            else:
                path=os.getcwd()
                self.msg.attachments[index].save()
        else:
            return f'File "{attachment_name}" not found.\nSave skipped.'
        return f'File saved in: {path}'            

class EmlParser:
    def __init__(self, file) -> None:
        self.file = file
        self.filenames = []
        self.hash_files = {}
    
    def get_header_info(self) -> dict:
        return dict_mapped(self.file)
    
    def get_attachments_names(self) -> str|list:
        msg = email.message_from_file(open(self.file), policy=default)
        if next(msg.iter_attachments(), None) is None:
            return "No attachments found"
        for element in msg.iter_attachments():
            if element.get_filename() not in self.filenames:
                self.filenames.append(element.get_filename())
        return self.filenames
    
    def calculate_hash(self) -> dict:
        msg = email.message_from_file(open(self.file), policy=default)
        for element in msg.iter_attachments():
            data = element.get_payload(decode=True)
            if element.get_filename() not in self.hash_files.keys():
                sha256 = hashlib.sha256()
                sha256.update(data)
                self.hash_files[element.get_filename()] = sha256.hexdigest()
        return self.hash_files

    def save_attachment(self, attachment_name:str, **kwargs) -> str:
        #questo if forse non serve
        #if len(self.filenames) < 1:
        #    self.get_attachments_names()
            
        msg = email.message_from_file(open(self.file), policy=default)
        
        if next(msg.iter_attachments(), None) is None:
            return "No attachments found"

        for element in msg.iter_attachments():
                if element.get_filename() == attachment_name:
                    path=os.getcwd()
                    with open(path + f'\\{attachment_name}', "wb") as fp:
                        fp.write(element.get_payload(decode=True))
        return f'File saved in: {path}'