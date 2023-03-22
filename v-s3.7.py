import shodan
import requests
import base64
import string
import random
import urllib
import re

#Create the Shodan API object
SHODAN_API_KEY = "Your API Key Here"
api = shodan.Shodan(SHODAN_API_KEY)

#Create a function to get the results from Shodan
def get_shodan_results(host):
    #Search Shodan
    try:
        # Lookup the host
        hostinfo = api.host(host)
        # Print general info
        print("""
            IP: {}
            Organization: {}
            Operating System: {}
        """.format(hostinfo['ip_str'],hostinfo.get('org', 'n/a'),hostinfo.get('os', 'n/a')))

        # Get all banners
        for item in hostinfo['data']:
            print("""
                Port: {}
                Banner: {}
            """.format(item['port'],item['data']))
    except shodan.APIError as e:
        print('Error: {}'.format(e))

#Create a function to get the results from the Google Hacking Database
def get_ghdb_results(domain):
    #Search the Google Hacking Database
    search_url = "http://www.exploit-db.com/ghdb/?action=search&q="+domain
    request = requests.get(search_url)
    response = request.content
    #Parse the results
    results = re.findall(r'<li>(.*?)</li>', response)
    #Print the results
    print("Google Hacking Database results for "+domain+":\n")
    for result in results:
        print(result)

#Create a function to fuzz the URL
def fuzz_url(domain):
    #Create a random string
    random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
    #Create the fuzzed URL
    fuzzed_url = domain + "/" + random_string
    #Print the fuzzed URL
    print("Fuzzed URL: "+fuzzed_url)
    #Make a request to the fuzzed URL
    try:
        request = requests.get(fuzzed_url)
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
    #Print the response code
    print("Response code: "+str(request.status_code))

#Create a function to test for XSS vulnerabilities
def test_xss(domain):
    #Create a random string
    random_string = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])
    #Encode the string
    encoded_string = urllib.parse.quote_plus(random_string)
    #Create the XSS payload
    payload = "<script>alert('"+encoded_string+"')</script>"
    #Encode the payload
    encoded_payload = base64.b64encode(payload.encode()).decode()
    #Create the XSS URL
    xss_url = domain + "/" + encoded_payload
    #Print the XSS URL
    print("XSS URL: "+xss_url)
    #Make a request to the XSS URL
    try:
        request = requests.get(xss_url)
    except requests.exceptions.RequestException as e:
        print('Error: {}'.format(e))
    #Print the response code
    print("Response code: "+str(request.status_code))

#Create a function to test for error codes
def test_error_codes(domain):
    #Create a list of error codes
    error_codes = [400, 401, 402, 403, 404, 500, 501, 502, 503, 504]
    #Loop through the list of error codes
    for error_code in error_codes:
        #Create the URL
        url = domain + "/" + str(error_code)
        #Make a request to the URL
        try:
            request = requests.get(url)
        except requests.exceptions.RequestException as e:
            print('Error: {}'.format(e))
        #Print the response code
        print("Response code for "+str(error_code)+": "+str(request.status_code))

#Main function
def main():
    #Prompt the user for a domain
    domain = input("Enter a domain: ")
    #Get the results from Shodan
    get_shodan_results(domain)
    #Get the results from the Google Hacking Database
    get_ghdb_results(domain)
    #Fuzz the URL
    fuzz_url(domain)
    #Test for XSS vulnerabilities
    test_xss(domain)
    #Test for error codes
    test_error_codes(domain)

#Run the main function
if __name__ == "__main__":
    main()
