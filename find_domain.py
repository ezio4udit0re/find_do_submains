import sys, requests
import json
import subprocess, re

def showhelp():
        print("""
Usage: python find_domain.py [OPTIONS]

[OPTIONS]
[+] Find Domain and Subdmain:
--ip     [IP ADDRESS]
[+] Find Subdomain:
--domain    [DOMAIN NAME]

""")


def get_sub(domain):
    text = subprocess.Popen(["./findomain-linux", "-t", domain], stdout=subprocess.PIPE)
    pipe = text.communicate()[0].decode()
    result = re.findall(r">>+\s{1}.*", pipe)
    for s in result:
        ip = get_ip(s)
        print(s +" : "+str(ip))

def get_ip(url):
    try:
        url = url.replace(">> ","")
        text = subprocess.Popen(["ping", "-c", "1","-n","-i","0.2","-W1","{0}".format(url)], stdout=subprocess.PIPE)
        pipe = text.communicate()[0].decode()
        result = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", pipe)
        if not result:
            return 0
        else:
            return result[0]
    except:
        print("")
def load_json(data):
    json1 = json.dumps(data)
    json_d = json.loads(json1)
    return json.loads(json_d).items()


def find_domain(ip):
    try:
        list_domain = []
        vt_apikey = "252708f32ca7b96d4b10e059bdc561a3a16d8b4b5721c9e7ec75342d887e0f1b"
        vt_url = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=%s&ip=%s"%(vt_apikey, ip)
        resp = requests.get(vt_url)
        data = resp.text
        #xuli_json
        dic = load_json(data)
    #========== for viewdns_info_api=================
        # apikey = "c49a6fdcd3462b034e32718b6da368eaa949450e"
        # url = "https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json" % (ip, apikey)
        # for key, value in dic1:
        #     if (key == "response"):
        #         json2 = json.dumps(value)
        # dic2 = json.loads(json2).items()
    #===========================================
        for key, value in dic:
            if (key == "resolutions"):
                list_domain = value
        print("Domain Founded in IP ADDRESS: "+ip+"\n")
        for i in list_domain:
            print("[+]"+i['hostname'])
        print("\n\nTotal domains found: %s \n\n" % (len(list_domain)))
        print("********Finding subdomain:*********\n")
        for i in list_domain:
            print("[+]"+i['hostname'])
            get_sub(i['hostname'])
            print("\n")
    except:
        print(".")

if __name__ == "__main__":
   if len(sys.argv) <= 2:
      showhelp()
      sys.exit()
   else:
      if(sys.argv[1] == "--ip"):
        find_domain(sys.argv[2])
      elif(sys.argv[1] == "--domain"):
        get_sub(sys.argv[2])
