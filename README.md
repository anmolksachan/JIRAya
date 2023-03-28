
# JIRA"YA - JIRA Yet Another vulnerability Analyzer by @FR13ND0x7f

<img width="955" alt="image" src="https://user-images.githubusercontent.com/60771253/228196580-f95a0fdf-adf9-4c04-93bb-75adb81e638b.png">

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

<img width="740" alt="image" src="https://user-images.githubusercontent.com/60771253/228210469-9995d1cb-bd2d-42c8-831f-6c206d788e0d.png">

`python JIRAya.py --TheTimeMachine <url/domain>` 

This module is inspired from my other tool "[The Time Machine](https://github.com/anmolksachan/thetimemachine)". This will test multiple JIRA instances at the URLs specified in the `<url/target>`.

## Tests performed

The following tests are performed against the JIRA instance:

-   Check for unauthenticated access to JIRA dashboards
-   Check for unauthenticated access to JIRA project categories
-   Check for unauthenticated access to JIRA resolutions
-   Check for unauthenticated access to installed JIRA gadgets
-   Check for unauthenticated access to JIRA admin projects
-   Check for CVE-2020-14179: Information disclosure about custom fields and custom SLA
-   Check for CVE-2019-3403: Information disclosure of all existing users on the JIRA server
-   Next update will be released soon with more test cases

## Author

-   Name: FR13ND0x7f
-   GitHub: [https://github.com/FR13ND0x7f](https://github.com/FR13ND0x7f)
-   Twitter: [https://twitter.com/fr13nd0x7f](https://twitter.com/fr13nd0x7f)

## License

This project is licensed under the MIT License - see the [LICENSE](https://raw.githubusercontent.com/anmolksachan/JIRAya/main/LICENSE) file for details.
