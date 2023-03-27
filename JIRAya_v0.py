import requests
import json

print("""

       █████ █████ ███████████     █████████   ██ ██ █████ █████   █████████  
      ░░███ ░░███ ░░███░░░░░███   ███░░░░░███ ░██░██░░███ ░░███   ███░░░░░███ 
       ░███  ░███  ░███    ░███  ░███    ░███ ░░ ░░  ░░███ ███   ░███    ░███ 
       ░███  ░███  ░██████████   ░███████████         ░░█████    ░███████████ 
       ░███  ░███  ░███░░░░░███  ░███░░░░░███          ░░███     ░███░░░░░███ 
 ███   ░███  ░███  ░███    ░███  ░███    ░███           ░███     ░███    ░███ 
░░████████   █████ █████   █████ █████   █████          █████    █████   █████
 ░░░░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░   ░░░░░          ░░░░░    ░░░░░   ░░░░░ 
                                     
                   JIRA Yet Another vulnerability Analyzer
""")

# User input
domain = input("Enter domain to check: ")

# WaybackURL API endpoint
wayback_url = f"https://archive.org/wayback/available?url={domain}"

# Retrieve WaybackURL snapshots of the domain
response = requests.get(wayback_url)
json_data = json.loads(response.text)
#snapshots = json_data['archived_snapshots']['closest']['url']
snapshots = json_data['archived_snapshots']

print(snapshots)

# Initialize variables to store results
vulnerabilities = []
dashboard_url = f"{snapshots}/rest/api/2/dashboard?maxResults=100"
project_category_url = f"{snapshots}/rest/api/2/projectCategory?maxResults=1000"
resolution_url = f"{snapshots}/rest/api/2/resolution"
gadgets_url = f"{snapshots}/rest/config/1.0/directory"
admin_projects_url = f"{snapshots}/rest/menu/latest/admin"
query_component_url = f"{snapshots}/rest//secure/QueryComponent!Default.jspa"
user_picker_url = f"{snapshots}/rest/api/2/user/picker?query=admin"

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
    print("The following vulnerabilities were found:")
    for vulnerability in vulnerabilities:
        print("- " + vulnerability)
else:
    print("No vulnerabilities were found.")
