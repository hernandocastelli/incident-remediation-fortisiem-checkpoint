# Automatic incident remediation with FortiSIEM and Checkpoint Firewall

This is a script to integrate FortiSIEM and Checkpoint using the Remediate Incident feature in FortiSIEM. The objective is to automatically execute a legacy script that can extract and publish IOC from incidents and use it in Checkpoint as an external IOC source. The script is written in Python and uses the modules of the existing version of Python of FortiSIEM 7.1.0, no need to install anything with pip, keeping it simple to avoid modifying the base O.S. There is not much information about how to process the incident with a legacy script, after some debugging I found that the incident information is stored in an XML file.

```
<?xml version="1.0" encoding="UTF-8" ?>
<incident incidentId="00000" organization="Super" repeatCount="1" ruleType="PH_RULE_FAILED_LOGON_MULTIPLE_ACCOUNTS" severity="9" status="0">
    <name>Multiple Logon Failures: Same Src and Dest and Multiple Accounts</name>
    <remediation>Identify the source of the incident and the user and make sure that it is a legitimate attempt to log on to the system. Make sure it is not a cached credential from another system while the primary user has changed credential. Make sure there are no other incidents from the source host that may indicate malware trying to gain access to other systems. Make sure there are no vulnerabilities on the source and destination hosts.</remediation>
    <description>Detects same source having excessive login failures at the same destination host but multiple distinct accounts are used during the logon failure</description>
    <policyID/>
    <displayTime>Mon Jun 10 19:35:00 ART 2024</displayTime>
    <incidentCategory>Security/Credential Access</incidentCategory>
    <incidentSource>
        <entry attribute="srcIpAddr" name="Source IP">000.000.000.000</entry>
    </incidentSource>
    <incidentTarget>
        <entry attribute="destName" name="Destination Host Name">HOST</entry>
        <entry attribute="destIpAddr" name="Destination IP">000.000.000.000</entry>
    </incidentTarget>
    <incidentDetails>
        <entry attribute="incidentCount" name="Triggered Event Count">3</entry>
    </incidentDetails>
    <affectedBizSrvc/>
    <identityLocation/>
    <mitreTactic>Credential Access</mitreTactic>
    <mitreTechniqueId>T1110.001</mitreTechniqueId>
</incident>
```
## Installation

1. Make an SSH conection to the FortiSIEM and create the directory and upload the files

    ```bash
    git clone https://github.com/hernandocastelli/incident-remediation-fortisiem-checkpoint.git script
    cd /script
    chown admin.admin src_ip.py
    chmod 770 src_ip.py
    mv src_ip.csv /var/www/html/
    cd /var/www/html
    chown admin.admin src_ip.csv
    chmod 660 src_ip.csv
    ```

## Usage

Go to an incident, click on the dropwdown Actions, select Remediate Incident, select Legacy Script and fill the text box with the path to the script /script/src_ip.py.
Click the Run button, if successful the message 'Success' will appear in green, otherwise the debug error will be printed.
The script will generate a csv file that respects the default checkpoint configuration, translating the incident severity from number to text, and some IP checks.
To check that the IP of the ticket has been saved, open a web browser and access the URL https://hostname_SIEM/src_ip.csv and check the contents of the file.

## Automatic remediation

### FortiSIEM

Create a new FortiSIEM rule for the incident that you want to remediate automatically, for more information on rules, go to https://help.fortinet.com/fsiem/7-1-0/Online-Help/HTML5_Help/Rules.htm
Then create a new FortiSIEM notification policy based on previously created rule and complete the option Run Remediation/Script with the path to the script. For more information about this go to https://help.fortinet.com/fsiem/7-1-0/Online-Help/HTML5_Help/Notification_Settings.htm

### Checkpoint

Follow the sk132193: https://support.checkpoint.com/results/sk/sk132193

## License

This project is licensed under the MIT License.