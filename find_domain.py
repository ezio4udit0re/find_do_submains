import sys, requests
import json
import subprocess, re

def showhelp():
        print("""
Usage: python find_domain.py [OPTIONS]

[OPTIONS]

-ip     [IP ADDRESS]

""")


def get_sub(string):
    text = subprocess.Popen(["./findomain-linux", "-t", string], stdout=subprocess.PIPE)
    pipe = text.communicate()[0].decode()
    result = re.findall(">>+\s{1}.*", pipe)
    for v in result:
        print("\t"+v)


def load_json(data):
    json1 = json.dumps(data)
    json_d = json.loads(json1)
    return json.loads(json_d).items()


def find_domain(ip):
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
    print("Domain Founded: \n\n")

    for i in list_domain:
        print("[+]"+i['hostname'])
        get_sub(i['hostname'])
        print("\n")
    print("\n\nTotal domains found: %s \n\n" %(len(list_domain)))


if __name__ == "__main__":
   if len(sys.argv) <= 2:
      showhelp()
      sys.exit()
   else:
      find_domain(sys.argv[2])