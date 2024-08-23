
# JIRA"YA - JIRA Yet Another vulnerability Analyzer by @FR13ND0x7f

<img width="955" alt="image" src="https://github.com/anmolksachan/anmolksachan.github.io/blob/main/img/JIRAya-Final.gif">

## What is JIRA?
JIRA is a popular project management and issue tracking software developed by Atlassian. It is widely used in software development teams to track and manage tasks, bugs, and issues throughout the software development process.

JIRA allows teams to create and track tasks or issues, assign them to team members, set priorities, and track progress. It also offers features such as workflows, custom fields, and reporting to help teams manage their projects effectively.

In addition to software development, JIRA can also be used for project management in other industries such as marketing, HR, and finance. It has become a popular tool due to its flexibility, ease of use, and ability to integrate with other software tools.

## What this tool is designed for?
This script is designed to help security analysts check for vulnerabilities on JIRA instances by running a series of tests against it.

## Note
This is an active scanner since it interacts with the host to check wheither is is running JIRA, then runs the test cases against it to identify the vulnerability.

## Requirements

-   Python 3.6+
-   requests package

## Usage

<img width="955" alt="image" src="https://user-images.githubusercontent.com/60771253/228196580-f95a0fdf-adf9-4c04-93bb-75adb81e638b.png">

You can run the script by running the `JIRAya.py` file with the following command line options:

### Check single JIRA instance

<img width="661" alt="image" src="https://user-images.githubusercontent.com/60771253/228197155-0f454af0-2367-44bb-9bc6-16965751d27b.png">

`python JIRAya.py --single <url/domain>` 

This will test a single JIRA instance at the specified URL.

### Check multiple JIRA instances via provided file

`python JIRAya.py --list <file>` 

<img width="593" alt="image" src="https://user-images.githubusercontent.com/60771253/228197986-5e4e0bc8-88df-4360-96d6-f0aecc51da44.png">

This will test multiple JIRA instances at the URLs specified in the `<file>`.

### Check multiple JIRA instances via Way Back URLs

<img width="740" alt="image" src="https://user-images.githubusercontent.com/60771253/228210895-64502965-3bb9-4ece-b547-03bd07f64cb4.png">

`python JIRAya.py --TheTimeMachine <url/domain>` 

This module is inspired from my other tool "[The Time Machine](https://github.com/anmolksachan/thetimemachine)". This will test multiple JIRA instances at the URLs specified in the `<url/target>`.

## Tests performed

The following tests are performed against the JIRA instance:

| Test case	| Description |
| --------- | -----|
| Unauthenticated access to JIRA dashboards	  | Check if the script can access JIRA dashboards without authentication |
| Unauthenticated access to JIRA project categories	     |  Check if the script can access JIRA project categories without authentication |
| Unauthenticated access to JIRA resolutions	       |  Check if the script can access JIRA resolutions without authentication   |
| Unauthenticated access to installed JIRA gadgets	      |   Check if the script can access installed JIRA gadgets without authentication  |
| Unauthenticated access to JIRA admin projects	      |  Check if the script can access JIRA admin projects without authentication   |
| CVE-2020-14179: Information disclosure about custom fields and custom SLA	     |   Check for information disclosure vulnerability that could be exploited to get custom field and custom SLA information  |
| CVE-2019-3403: Information disclosure of all existing users on the JIRA server      |  Check for information disclosure vulnerability that could be exploited to get all existing users on the JIRA server   |
| CVE-2019-8449: Information disclosure of all users in JIRA server   |  Check for information disclosure vulnerability that could be exploited to get all users on the JIRA server   |
| Blind SSRF vulnerability	      |  Check if the script can send HTTP requests to an external URL without the user's knowledge   |
| Cross-Site Scripting (XSS) vulnerability      |   Check if the script is vulnerable to cross-site scripting (XSS) attacks  |
| Authentication Bypass in Seraph - CVE-2022-0540 | https://github.com/Pear1y/CVE-2022-0540-RCE |
| Authentication Bypass in Seraph - CVE-2022-0540 | Limited attack, can view/ edit configurations |

-   Next update will be released soon with more test cases
-   Reference: [Atlassian Jira CVE Details](https://www.cvedetails.com/vulnerability-list/vendor_id-3578/product_id-8170/Atlassian-Jira.html)

## Author

-   Name: FR13ND0x7f
-   GitHub: [https://github.com/FR13ND0x7f](https://github.com/FR13ND0x7f)
-   Twitter: [https://twitter.com/fr13nd0x7f](https://twitter.com/fr13nd0x7f)

## License

This project is licensed under the MIT License - see the [LICENSE](https://raw.githubusercontent.com/anmolksachan/JIRAya/main/LICENSE) file for details.
