import dns
import dns.message as dns_message
import dns.query as dns_query
import argparse
import time
import datetime
import sys

# set up argument parsing
parser = argparse.ArgumentParser(description="Resolve a domain name to an IP adress")
parser.add_argument('domain', help='the domain name to resolve.')
parser.add_argument('-v', '--verbose', action='store_true', help='print extra information during runtime about the program\'s current operations.')
args = parser.parse_args()
original_domain = args.domain
verbose = args.verbose

# list of dns root servers to query
root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12",
                "199.7.91.13", "192.203.230.10", "192.5.5.241",
                "192.112.36.4", "198.97.190.53", "192.36.148.17",
                "192.58.128.30", "193.0.14.129", "199.7.83.42", 
                "202.12.27.33"]

# constants that will be used in return value of resolve_domain()
FINAL = 0
AUTH = 1
CNAME = 2
ERROR = -1

# main repeatedly calls resolve_domain() until resolve_domain() returns the final IP 
def main():
    answer = None
    # what are we currently trying to resolve, final IP of input domain by default
    looking_for = FINAL 

    # if we encounter a AUTH server, we will have to remember what domain name we were previously looking for
    # Could be nested AUTH servers so this needs to be a list, not just a var
    prev_domain = [original_domain]

    # our starting query should be asking for the input domain
    domain = original_domain
    query = dns_message.make_query(domain, 'A')

    start = time.time()
    date = datetime.datetime.now()

    for root_server in root_servers:
        # start at the root
        server_to_query = root_server

        # call resolve_domain() until resolve_domain() returns the final answer
        while(answer == None):
            query_response = resolve_domain(domain, server_to_query, query)
            
            # Process the results
            # if error, try again at new root
            if (query_response[1] == ERROR):
                verbose_print("Resolution failed, retrying at new server\n")
                break

            # if final answer
            if (query_response[1] == FINAL):
                # if we were looking to resolve an AUTH, we should now ask the resolved
                # AUTH IP for our original input domain
                if(looking_for == AUTH): 
                    server_to_query = query_response[0].answer[0][0].to_text()
                    verbose_print(f"Auth server {domain} resolved to IP address {server_to_query}\n") 
                    domain = prev_domain.pop()  # get the domain we were previously looking for
                    query = dns_message.make_query(domain, 'A') 
                    looking_for = FINAL                
                    continue

                # otherwise, we found the answer
                answer = query_response[0].answer
                verbose_print("Query response contains answer!\n")
                answer_print(query_response[0], start, date)
                sys.exit(0)

            # if CNAME, that is the new domain to resolve
            if (query_response[1] == CNAME):
                domain = query_response[0].answer[0][0].to_text() # get the CNAME name as a str
                verbose_print(f"Query resolved to CNAME {domain} Beginning resolution of CNAME from root\n")
                server_to_query = root_server
                query = dns_message.make_query(domain, 'A')
                looking_for = FINAL
                continue

            # if AUTH, that is the new domain to resolve, but save our current domain to query the AUTH later
            if (query_response[1] == AUTH):
                prev_domain.append(domain)  # save the current domain being searched
                domain = query_response[0].authority[0][0].to_text() # get the AUTH NS as a str
                verbose_print(f"Record for {prev_domain[-1]} stored in authority server {domain}. Beginning resolution of auth server from root\n")
                server_to_query = root_server
                query = dns_message.make_query(domain, 'A')
                looking_for = AUTH
                continue
    
    # if we exit the for loop without exiting, we failed
    error_print(f"Resolution failed at all root servers. Unable to resolve {original_domain}")

# given a domain name, resolve it as much as possible. Querying 
# begins at server_to_query and iteratively continues until we 
# receive an ANSWER or the name of an AUTHORITY Name Server
# to query next 
#     return value - a tuple (response, type) where response is 
#     a dnspython message containing our answer and type is an integer indicating
#     whether the answer is a CNAME, authoritative NS, or the IP of the 
#     requested domain
#     On error, answer is None and type is -1
def resolve_domain(rs_domain, rs_server, rs_query):
    response = None

    # while loop to iterively resolve domain
    while(True):
            # send a udp query to the current server to query
            verbose_print(f"Sending DNS query for {rs_domain} to DNS server at {rs_server}")
            try:
                response = dns_query.udp(rs_query, rs_server, timeout=2)
            except dns.exception.Timeout:
                verbose_print(f"DNS query timed out after 2 seconds.")
                break 
            except Exception as ex:
                verbose_print(f"DNS query raised unexpected exception of type {type(ex)}.")
                break

            # check the rcode
            rcode = dns.rcode.to_text(response.rcode())
            if(rcode != 'NOERROR'): 
                if(rcode == 'NXDOMAIN'):
                    error_print(f"Error: response returned with rcode {rcode}. This domain does not exist")
                    sys.exit(1)
                verbose_print(f"Error: response returned with faulty rcode {rcode}.")
                break
            # more extensive printing function only used for development
            # debug_print_response(response)

            # process response
            # if there is a answer, we should return it
            if(len(response.answer) > 0):
                # if not an ip address, its CNAME
                if(not dns.inet.is_address(response.answer[0][0].to_text())):
                    return (response, CNAME)
                # if IP, its answer
                return (response, FINAL)

            # otherwise, see if we were given the IP of a name server we can follow up with
            elif(len(response.additional) > 0):
                for name_server in response.additional:
                    # get IPv4 addresses only
                    ns_address = name_server[0].to_text()
                    if(dns.inet.af_for_address(ns_address) == 2):
                        rs_server = ns_address
                        verbose_print(f"Name server at address {rs_server} found in response.\n")
                        break
                # if there are no IPv4 addresses, return an error
                else:
                    break
    
            # otherwise, try resolving AUTHORITY
            elif(len(response.authority) > 0):
                return(response, AUTH)
            
            # if there was nothing at all, something has gone wrong
            else:
                break  # breaks instead of many return statements to easily change return value - only have to modify one line
    
    # if we exited the while loop without returning, its an error
    return (None, ERROR)

def answer_print(response, start, date):
    print("QUESTION SECTION:")
    for result in response.question:
        words = result.to_text().split(' ')
        words[0] = original_domain
        print(" ".join(words))

    print("\nANSWER SECTION:")
    for address in response.answer:
        words = address.to_text().split(' ')
        words[0] = original_domain
        print(" ".join(words))

    query_time = (int)((time.time() - start)*1000)
    print("\nQuery time: " + str(query_time) + " msec")
    print("WHEN: " + str(date))

def verbose_print(msg):
    if(verbose):
        print(msg)

# separate function only because I originally had color formatting for error codes
# removed because ANSI color formatting is system dependent and i didn't want to mess up potential grading scripts
# :(
def error_print(msg):
    print(msg)

# call main function 
if(__name__ == '__main__'):
    main()


# print all fields of a DNS field, only used during development
# def debug_print_response(response):
#     print("\nQUESTION SECTION:")
#     for question in response.question:
#         print(question)

#     print("`\`nANSWER SECTION:")
#     for answer in response.answer:
#         print(answer)

#     print("\nAUTHORITY SECTION:")
#     for answer in response.authority:
#         print(answer)

#     print("\nADDITIONAL SECTION:")
#     for additional in response.additional:
#         print(additional)

#     print("\n")