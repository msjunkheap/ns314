#!/usr/bin/env python

import sys, time, socket, struct
from daemon import Daemon
from ns314 import *

# Open our log file to print for errors
LOG = open('debug.log', 'w')

# Bind to localhost on port 5300
IP = '127.0.0.1'
PORT = 5300

# Create our struct format to separate the header into variables
HEADER_STRUCT = '!HBBHHHH'

# Define our classes
qclasses = {
    1: 'IN',
    3: 'CH',
    255: '*'
    }

# Define our record types
qtypes = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
#    6: 'SOA',
#    12: 'PTR',
#    15: 'MX',
#    16: 'TXT',
#    17: 'RP',
#    28: 'AAAA',
##    29: 'LOC',
#    33: 'SRV',
##    35: 'NAPTR',
##    39: 'DNAME',
##    44: 'SSHFP',
##    45: 'IPSECKEY',
##    47: 'NSEC',
##    48: 'DNSKEY',
#    99: 'SPF',
#    251: 'IXFR',
#    252: 'AXFR',
#    255: '*'#,
    }

# Define our logging function to write messages to the error log
def log(lists = None, dct = None):
    if lists != None:
        LOG.write(' '.join([int(l) for l in lists]))
    if dct != None:
        LOG.write(' '.join(dct.values()))
    #LOG.write(' '.join([str(m) for m in messages]))
    LOG.write('\n')
    LOG.flush()

def check_record(query_record, qtype, qclass):    # Check if we've got the record
    def cname_recurse(iteration, ctype, cclass, req_record):
        i += 1
        if i <= 2:    # Iterate recursively up to 3 times to find the target of our CNAME, otherwise return None
            c_answer = [ c_record_obj for c_record_obj in records if cclass == c_record_obj['qclass'] and req_record == c_record_obj['rr'] ]
            if not c_answer:    # If we didn't find a record matching our cname target try again ########################################### add exception to make sure this won't succeed even if c_answer is empty
                target = cname_recurse(iteration, qtype, qclass, req_record)
            else:
                target = c_answer
        else:
            target = None
        return target
    # End cname_recurse function

    def cname_check(check_obj):
        if check_obj['qclass'] == 1 and check_obj['qtype'] == 5:    # If the record is an IN CNAME, recurse
            check_answer = cname_recurse(0, check_obj['qtype'], check_obj['qclass'], check_obj['labels'])
        if check_answer is None:         # If we received no results by checking the cname against our cache return the CNAME
            check_answer = check_obj
        return check_answer
    # End cname_check function

    # We're going to cheat by adding records into a list statically. We'll make this pull from a sqlite DB later
    a_record = rr.A(True, 'ns314.com.', 300, 1, (127, 0, 0, 1))            # Example A record
    cname_record = rr.CNAME(True, 'www.ns314.com.', 300, 1, 'ns314.com.')        # Example CNAME record (might consider making this a list of labels)
    records = [a_record, cname_record]

    # Let's test to see how difficult it would be to make this list in the same format as the cname search function
    answer = [ cname_check(record_obj) for record_obj in records if qclass == record_obj['qclass'] and query_record == record_obj['rr'] ]

#    answer = []    # Initialize our answer list so we can append answer objects at will
#    for record_obj in records:    # Check the records list to find our query.
#        #if qclasses.get(qclass) == record_obj['qclass'] and query_record == record_obj['rr']: # and qtype == record_obj['qtype']:
#        if qclass == record_obj['qclass'] and query_record == record_obj['rr']:    # ARCOUNT
#            if record_obj['qtype'] == 5:    # If we got a CNAME from our records iterate over the objects again to see if we have the target
#                cname_result = cname_recurse(0, record_obj['qtype'], record_obj['qclass'], query_record)
#                for cname_target in records:
#                    
#            if qtype == record_obj['qtype']:
#                answer.append(record_obj)        # Add our record object to the stack or answers

    if not answer:
        answer = None
    return answer

#def check_cache(record, qtype):
#    pass

def format_label(labels, recv = True):
    if recv:    # If we're converting a received label convert it to the standard example.com. format
        formatted_label = '.'.join(labels)+'.'
    else:
        formatted_label = '.'.split(labels)
        if formatted_label[-1] == '.':
            formatted_label = formatted_label[:-1]            
    return formatted_label

def parse_request(input):
    # Strip the header (12 bytes) from the request and slice it into separate variables using our struct pattern
    ID, DATA1, DATA2, QDCT, ANCT, NSCT, ARCT = struct.unpack(HEADER_STRUCT, input[:12])    
    BODY = input[12:]    # Put the rest of the request into its own variable
    labels = []        # Create a list to store each section of the request name (mail, ns314, com)
    while ord(BODY[0]):        # While the first character of BODY is not an unsigned char of 0 denoting the end of the request string
        length = ord(BODY[0])        # The length of our string is the first byte
        label = BODY[1:length+1]    # Grab the rest of the string using our length
        BODY = BODY[length+1:]        # Cut the string we extracted off the front of the data
        labels.append(label)        # Add the string to our list of labels
    QTYPE = struct.unpack('!H', BODY[1:3])[0]    # Pull the QTYPE from the request
    QCLASS = struct.unpack('!H', BODY[3:5])[0]    # Pull the QCLASS of the request (it's going to be IN, except for cases of black magic)
    QR = DATA1 >> 7            # Shift the 8th digit of DATA1 to the first and save it as QR
    OPCODE = (DATA1 & 0x7F) >> 3    # AND 0x7F against DATA1 to cut off the last char, and shift the smallest three digits off the end
    AA = (DATA1 & 0x04) >> 2    # AND DATA1 and 0x04, then shift two digits off the end
    TC = (DATA1 & 0x02) >> 1    # AND DATA1 and 0x02, then shift a digit off the end
    RD = (DATA1 & 0x01)        # AND DATA1 and 0x01
    RA = DATA2 >> 7            # Shift 7 digits off the end of DATA2 and save the last digit
    Z  = (DATA2 & 0x70) >> 4    # AND DATA2 and 0x70 then shift 4 digits off the end
    RCODE = (DATA2 & 0x0F)        # AND DATA2 and 0x0F
    # Return our header data in a list
    return {
        'ID': ID,        # Bytes 1-2 - Unique Request ID
        'DATA1': DATA1,        # Byte 3 - QR, Opcode (4 bit), AA, TC, RD
        'DATA2': DATA2,        # Byte 4 - RA, Z (3 bit), RCode (4 bit)
        'QR': QR,        # Byte 3, bit 7 - Query (0), Response (1)
        'OPCODE': OPCODE,    # Byte 3, bits 3-6 - Standard query (0), Inverse query (1), Server status request (2)
        'AA': AA,        # Byte 3, bit 2 - Authoritative Answer
        'TC': TC,        # Byte 3, bit 1 - TrunCated (indicates message is truncated for longer requests)
        'RD': RD,        # Byte 3, bit 0 - Recursion desired
        'RA': RA,        # Byte 4, bit 7 - Recursion available
        'Z': Z,            # Byte 4, bits 4-6 - Not used
        'RCODE': RCODE,        # Byte 4, bit 0-3 - Response code - No error 0, Format error 1, Server failure 2, Does not exist 3, Query refused 5
        'QDCT': QDCT,        # Bytes 5-6
        'ANCT': ANCT,        # Bytes 7-8
        'NSCT': NSCT,        # Bytes 9-10
        'ARCT': ARCT,        # Bytes 11-12
        'labels': labels,    # Variable length
        'QTYPE': QTYPE,        # A, CNAME, NS, etc.
        'QCLASS': QCLASS    # IN (Internet), CH (Chaos), etc.
        }

def build_response(request):
    record = format_label(request['labels'], True)        # Convert our labels into standard DNS format before checking, e.g. example.com.
    result = check_record(record, request['QTYPE'], request['QCLASS'])    # Check to see if we have an answer
    log(dicts = result[0])
    if result != None:            # Return the records here
        aa = result['aa']        # Test if our answer is authoritative
        answer = result['answer']    # IP address for our answer
        ttl = result['ttl']        # TTL for our answer
        ancount = 1            # Set the answer count to 1 since we're only returning one record
    else:
        # Handle the error if we receive no results
        aa = False
        ancount = 0

    response = [] # Build a list to put our request in
    data1 = request['DATA1']    # Start off with what we were given as a template
    #data1 = (data1 & 0xFE)        # Set recursion desired off for our response ((not necessary, can match what the client sent us))
    data1 = (data1 | 0x80)        # Set answer as a response
    if aa:                # Check if our answer is authoritative
        data1 = (data1 | 0x04)    # Set our AA bit as authoritative

    data2 = request['DATA2']    # Start with our request byte as a template
    data2 = (data2 | 0x80)        # Set recursion available to 1, just because


    qdcount = 0        # Set QDCOUNT to 0 because we're not asking anything back from the client
    nscount = 0        # Set NSCOUNT to 0 for now since we are claiming to be authoritative
    arcount = 0        # Set ARCOUNT to 0 since we aren't forwarding requests to any other name servers

    #log(HEADER_STRUCT, request['ID'], data1, data2, qdcount, ancount, nscount, arcount)    # Log things and stuff 
    response.append(
        struct.pack(HEADER_STRUCT,    # Use our header struct pattern to build the response header
            request['ID'],        # Set our response ID to match the incoming request
            data1,            # Insert our DATA1 configuration byte
            data2,            # Insert our DATA2 configuration byte
            qdcount,    # Number of entries in the question section (should match request, but we're going to ignore anything but the first question)
            ancount,    # Number of resource records in the answer section
            nscount,    # Number of name server resource records in the authority records section
            arcount        # Number of resource records in the additional records section
        )
    )
    
    for label in request['labels']:            # Run through our list of labels
        response.append(chr(len(label)))    # Append the string length before appending the string itself
        response.append(label)
    response.append('\0')                # Finish our label list with a 1 byte binary zero to signify the end of the response labels
    response.append(
        struct.pack('!HHIH',         # Pack our answer response
            request['QTYPE'],
            request['QCLASS'], 
            ttl, 
            len(answer)
        )
    )    
    #log(len(answer), *answer)
    #print(len(answer), answer)
    response.append(
        struct.pack('!BBBB', *answer))    # Send back the IP address in binary format
    return ''.join(response)            # Concatenate everything into one string

class MyDaemon(Daemon):
    def run(self):
        sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        sock.bind( (IP, PORT) )

        while True:
            data, addr = sock.recvfrom( 512 )        # Save the packet data and client address
            request = parse_request(data)            # Parse the request to a list
            log(request)                    # Log the request to our error log
            packet = build_response(request)        # Create our response to send back
            #log(packet)                    # Log the request to our error log
            sock.sendto(packet, addr)            # Return our processed response back to the client

if __name__ == "__main__":
    daemon = MyDaemon('/tmp/dns-daemon.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'run' == sys.argv[1]:
            daemon.run()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
