#!/usr/bin/env python

class packet:
    def __init__(self, aa, rr, ttl, qclass, answer):
        self.data = {
                'aa': aa,
                'rr': rr,
                'ttl': ttl,
                'qclass': qclass,
                'type_name': 'A',
                'qtype': 1,
                'answer': answer
            }

    def printargs(self):
        print self['aa']
        print self['rr']
        print self['ttl']
        print self['qclass']
        print self['type_name']
        print self['qtype']
        print self['answer']

    def __del__(self):
        del self.data

    def __getitem__(self, name):
        if isinstance(name, str):
            if name in self.data:
                return self.data[name]
            else:
                raise KeyError('NonExistentItem')
        else:
            return None


    def parse(input):
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
