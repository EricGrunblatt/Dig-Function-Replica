#!/usr/bin/python3

from dns import message, query, name, rdataclass, rdatatype
from datetime import datetime
import time

ROOT_DNS_SERVERS = ["198.41.0.4","199.9.14.201", "192.33.4.12","199.7.91.13","192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
cannotResolve = False

# The main function that prints all of the details in addition to setting up the recursive calls
def dns_resolver():
    # Prompt user to enter a domain
    url = input("Please enter a domain: ")
    req = message.make_query(url, rdatatype.A).question[0]
    global cannotResolve

    # Start query time, and get data/time of request for WHEN
    whenDateTime = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
    startTime = time.time()
    root = find_root_from_domain(url)
    res = []
    if root:
        res  = rec_lookup(url, root, root)
    endTime = time.time()

    # Combining domain and IP address for top of answer section
    lastAnswer = str(res[-1])
    fullArr = lastAnswer.split(" ")
    lastAnswerArr = fullArr[len(fullArr)-5:len(fullArr)]
    lastAnswerArr[0] = url + "."
    domainIP = ' '.join([str(s) for s in lastAnswerArr])
    
    # Print the main request
    print("\nQUESTION SECTION:")
    print(req)

    if cannotResolve == True or len(res) == 0:
        print("\nUnable to resolve ", url)
    else:
        # Print all responses by iterating through list
        print("\nANSWER SECTION:")
        print(domainIP)
        for ans in res:
            print(ans)
    
    # Query time and WHEN section
    queryTime = 1000*(endTime - startTime) # Convert from sec to ms
    print("\nQuery time: %d msec" % queryTime)
    print("WHEN: ", whenDateTime)

# The recursive call function that is used to gather all of the answers and place them all in a list to be printed later
# url: domain name inputted by the user
# ip: ip address from response (can be root server at times)
# root: root server found from find_root_from_domain() function
def rec_lookup(url: str, ip: str, root: str):
    global cannotResolve
    try:
        response = query.udp(message.make_query(url, rdatatype.A, 1), ip, 1)
    except:
        cannotResolve = True
        return None
    allAnswersList = []

    if response.answer:
        for x in response.answer:
            allAnswersList.append(response.answer[0])
        tempCname = response.get_rrset(message.ANSWER, name.from_text(response.answer[0].name.to_text()), rdataclass.IN, rdatatype.CNAME)
        currCname = None
        if tempCname:
            currCname = tempCname[0].to_text()
            newCname = rec_lookup(currCname, root, root)
            if newCname:
                allAnswersList += newCname
        return allAnswersList
    
    elif response.additional:
        # Check contents in response.additional by using get_rrset for 'IN A'
        tempNS = response.get_rrset(message.ADDITIONAL, name.from_text(response.additional[0].name.to_text()), rdataclass.IN, rdatatype.A)
        newNS = None
        if tempNS:
            newNS = tempNS[0].to_text()
        return rec_lookup(url, newNS, root)
    
    else:
        if len(response.authority) < 1:
            cannotResolve = True
            return None
        tempRrset = response.get_rrset(message.AUTHORITY, name.from_text(response.authority[0].name.to_text()), rdataclass.IN, rdatatype.NS)
        if tempRrset:
            authority = tempRrset[0].to_text()

            # Find name server from what get_rrset produced and use it as the ip address in next recursive call
            nameServer = rec_lookup(authority, root, root)
            if nameServer:
                return rec_lookup(url, nameServer[0][0].to_text(), root)
        if len(response.answer) >= 1:
            allAnswersList.append(response.answer[0])
        else:
            cannotResolve = True
            return None
        return allAnswersList


# Function to find the root server 
# domain: domain name inputted by the user
def find_root_from_domain(domain: str):
    global cannotResolve
    # Loop through all DNS servers in list
    for server in ROOT_DNS_SERVERS:
        try:
            # Return the name server if there is a successful response from get_rrset
            currMessage = message.make_query(domain, rdatatype.NS, 1)
            try:
                response = query.udp(currMessage, server, 1)
            except:
                print("Cannot connect to root server ", server)
                exit(-1)
            tempNS = response.get_rrset(message.ADDITIONAL, name.from_text(response.additional[0].name.to_text()), rdataclass.IN, rdatatype.A)
            newNS = None
            if tempNS:
                newNS = tempNS[0].to_text()
            return newNS

        except:
            # If last returned None, then all root servers are down
            if server == ROOT_DNS_SERVERS[-1]:
                print("All root DNS servers are down.")
                cannotResolve = True
                exit(-1)
            continue

    print("Cannot get TLD of %s" % domain)
    exit(-1)

if __name__ == "__main__":
    dns_resolver()
    