import argparse
import requests
from urllib.parse import urlparse

def banner():
    print("""
           █████ █████ ███████████     █████████   ██ ██ █████ █████   █████████  
          ░░███ ░░███ ░░███░░░░░███   ███░░░░░███ ░██░██░░███ ░░███   ███░░░░░███ 
           ░███  ░███  ░███    ░███  ░███    ░███ ░░ ░░  ░░███ ███   ░███    ░███ 
           ░███  ░███  ░██████████   ░███████████         ░░█████    ░███████████ 
           ░███  ░███  ░███░░░░░███  ░███░░░░░███          ░░███     ░███░░░░░███ 
     ███   ░███  ░███  ░███    ░███  ░███    ░███           ░███     ░███    ░███ 
    ░░████████   █████ █████   █████ █████   █████          █████    █████   █████
     ░░░░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░   ░░░░░          ░░░░░    ░░░░░   ░░░░░ 
                                         
             JIRA Yet Another vulnerability Analyzer by @FR13ND0x7f
    """)

def JIRA_TestCases(url):
    # Initialize variables to store results
    vulnerabilities = []
    dashboard_url = f"{url}/rest/api/2/dashboard?maxResults=100"
    project_category_url = f"{url}/rest/api/2/projectCategory?maxResults=1000"
    resolution_url = f"{url}/rest/api/2/resolution"
    gadgets_url = f"{url}/rest/config/1.0/directory"
    admin_projects_url = f"{url}/rest/menu/latest/admin"
    query_component_url = f"{url}/rest//secure/QueryComponent!Default.jspa"
    user_picker_url = f"{url}/rest/api/2/user/picker?query=admin"

    #print("dashboard URL is: " + dashboard_url);

    # Check for unauthenticated access to JIRA dashboards
    try:
        response = requests.get(dashboard_url)
        if response.status_code == 200:
            vulnerabilities.append("Unauthenticated access to JIRA dashboards")
    except:
        pass

    # Check for unauthenticated access to JIRA project categories
    try:
        response = requests.get(project_category_url)
        if response.status_code == 200:
            vulnerabilities.append("Unauthenticated access to JIRA project categories")
    except:
        pass

    # Check for unauthenticated access to JIRA resolutions
    try:
        response = requests.get(resolution_url)
        if response.status_code == 200:
            vulnerabilities.append("Unauthenticated access to JIRA resolutions")
    except:
        pass

    # Check for unauthenticated access to installed JIRA gadgets
    try:
        response = requests.get(gadgets_url)
        if response.status_code == 200:
            vulnerabilities.append("Unauthenticated access to installed JIRA gadgets")
    except:
        pass

    # Check for unauthenticated access to JIRA admin projects
    try:
        response = requests.get(admin_projects_url)
        if response.status_code == 200:
            vulnerabilities.append("Unauthenticated access to JIRA admin projects")
    except:
        pass

    # Check for CVE-2020-14179
    try:
        response = requests.get(query_component_url)
        if response.status_code == 200 and "custom field" in response.text:
            vulnerabilities.append("CVE-2020-14179: Information disclosure about custom fields and custom SLA")
    except:
        pass

    # Check for CVE-2019-3403
    try:
        response = requests.get(user_picker_url)
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities.append("CVE-2019-3403: Information disclosure of all existing users on the JIRA server")
    except:
        pass

    # Report the results of the analysis to the user
    if vulnerabilities:
        print("+ The following vulnerabilities were found:")
        for vulnerability in vulnerabilities:
            print("- " + vulnerability)
    else:
        print("- No vulnerabilities were found.")

def check_jira(url):
    if not url.startswith("http") or url.startswith("https"):
        url = "https://" + url
        print("[Scanning] : " + url)

    try:
        response = requests.get(url + "/rest/api/2/serverInfo")
        if response.status_code == 200 and "serverTitle" in response.json():
            print("+ JIRA is running on:", url)
            JIRA_TestCases(url)            

        else:
            print("- JIRA is not running on:", url)
    except:
        print("+ JIRA is not running on:", url)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Check if JIRA is running on a server or list of servers")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--single", "-s", metavar="URL", help="Check if JIRA is running on a single server")
    group.add_argument("--list", "-l", metavar="FILE", help="Check if JIRA is running on a list of servers")
    group.add_argument("--TheTimeMachine", "--thetimemachine","-ttm", metavar="URL", help="The Time Machine will do subdomain enumeration for you")
    args = parser.parse_args()

    if args.single:
        check_jira(args.single)
    elif args.TheTimeMachine:
        url = f'https://web.archive.org/cdx/search/cdx?url=*.{args.TheTimeMachine}/*&output=txt&fl=original&collapse=urlkey&page=/'
        print(f"\nTarget Loaded: "+args.TheTimeMachine)
        response = requests.get(url)
        url_list = response.text
        file = (args.TheTimeMachine+".txt")
        print("Storing in "+file)
        with open(file, "w") as f:
            f.write(url_list)

        urls = set()
        with open(file, "r") as f:
            for line in f:
                url = line.strip()
                domain = urlparse(url).netloc
                if domain not in urls:
                    urls.add(domain)
                    check_jira(domain)
    else:
        urls = set()
        with open(args.list, "r") as file:
            for line in file:
                url = line.strip()
                domain = urlparse(url).netloc
                if domain not in urls:
                    urls.add(domain)
                    check_jira(domain)

if __name__ == "__main__":
    main()
