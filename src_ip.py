import os,sys
import csv
import xml.dom.minidom
import mmap
from ipaddress import ip_address

def severity_from_number(number):
    """Returns the severity of the incident in Checkpoint format (low|medium|high)
    
    Arguments:
        number (string): numerical severity assigned by fortisiem to the incident
    """
    number = int(number)
    if number <= 4:
        text = "low"
    elif number >= 9:
        text = "high"
    else:
        text = "medium"
    return text

def is_public_ip(ip):
    return False if (ip_address(ip).is_private) else True

def is_new_ioc(ioc,fileIOC):
    """Returns True if the IOC already exists in the file.
    
    Arguments:
        ioc (string): ioc to search in the file
        fileIOC (string): path to the file src_ip.csv
    """
    if(os.stat(fileIOC).st_size != 0):
        with open(fileIOC, 'rb', 0) as file:
            s = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
            if s.find(ioc.encode()) != -1:
                return False
    return True

def main(args):
    doc = xml.dom.minidom.parse(args[1])
    fileIOC = '/var/www/html/src_ip.csv'

    if (doc.firstChild.tagName == "incident"):

        # Get source IP from incident xml file
        ips = doc.getElementsByTagName("incidentSource")
        for ip in ips:
            srcIpAddr = ip.getElementsByTagName("entry")[0]
        value = srcIpAddr.firstChild.data

        if is_public_ip(value) and is_new_ioc(value, fileIOC):
            id = doc.getElementsByTagName("incident")[0]
            uniq = id.getAttribute("incidentId")
            severityNumber = id.getAttribute("severity")
            cat = doc.getElementsByTagName("incidentCategory")[0]
            category = cat.firstChild.data
            ips = doc.getElementsByTagName("incidentSource")
            type = "IP"
            confidence = "high"
            severity = severity_from_number(severityNumber)
            product = "AB"
            comment = uniq + " - " + category

            # Write the ioc in the file in Checkpoint format.
            # Header: #UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT
            with open(fileIOC, 'a', newline='') as file:
                writer = csv.writer(file)
                field = [ uniq, value, type, confidence, severity, product, comment ]
                writer.writerow(field)

if __name__ == "__main__":
    main(sys.argv)
