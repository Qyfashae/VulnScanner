import shodan
import requests
import base64
import string
import random
import urllib
import re

SHODAN_API_KEY = "Your API Key Here"
api = shodan.Shodan(SHODAN_API_KEY)

def get_shodan_results(host):
    try:
        hostinfo = api.host(host)
        print("""
            IP: {}
            Organization: {}
            Operating System: {}
        """.format(hostinfo['ip_str'],hostinfo.get('org', 'n/a'),hostinfo.get('os', 'n/a')))

        for item in hostinfo['data']:
            print("""
                Port: {}
                Banner: {}
            """.format(item['port'],item['data']))
    except shodan.APIError as e:
        print('Error: {}'.format(e))

def get_ghdb_results(domain):
    search_url = "http://www.exploit-db.com/ghdb/?action=search&q="+domain
    request = requests.get(search_url)
    response = request.content
    results = re.findall(r'<li>(.*?)</li>', response)
    print("Google Hacking Database results for "+domain+":\n")
    for result in results:
        print(result)

def fuzz_url(domain):
    random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
    fuzzed_url = domain + "/" + random_string
    print("Fuzzed URL: "+fuzzed_url)
    try:
        request = requests.get(fuzzed_url)
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
    print("Response code: "+str(request.status_code))

def test_xss(domain):
    random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
    encoded_string = urllib.parse.quote_plus(random_string)
    payload = "<script>alert('"+encoded_string+"')</script>"
    encoded_payload = base64.b64encode(payload.encode()).decode()
    xss_url = domain + "/" + encoded_payload
    print("XSS URL: "+xss_url)
    try:
        request = requests.get(xss_url)
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
    print("Response code: "+str(request.status_code))

def test_error_codes(domain):
    error_codes = [400, 401, 402, 403, 404, 500, 501, 502, 503, 504]
    for error_code in error_codes:
        url = domain + "/" + str(error_code)
        try:
            request = requests.get(url)
        except requests.exceptions.RequestException as e:
            print('Error: {}'.format(e))
        print("Response code for "+str(error_code)+": "+str(request.status_code))

def main():
    domain = input("Enter a domain: ")
    get_shodan_results(domain)
    get_ghdb_results(domain)
    fuzz_url(domain)
    test_xss(domain)
    test_error_codes(domain)

if __name__ == "__main__":
    main()
