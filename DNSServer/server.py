from socket import *
from struct import pack, unpack
from time import time
from random import randint

from typing_extensions import Self

SERVER_ADDR = '0.0.0.0' # IP address of interface to bind to
SERVER_PORT = 10053 # so we can run this unprivileged (and avoid conflicts)
BUFFER_SIZE = 2048 # buffer size for receiving UDP datagrams

# DNS record class
class Record:
    def __init__(self, recordType: str, name: str, value: str | None = None, ttl: int = -1):
        self.recordType = recordType # record type (A/CNAME/NS)
        self.name = name.strip() # the record's name (e.g. example.com)
        self.value = value # the record's value
        self.ttl = ttl # the record's TTL (< 0 means no expiry)
        self.queriedAt: float = time() # timestamp of when this record was queried from the upstream DNS server
    
    # get string representation of the record (for debugging, mostly)
    def __repr__(self) -> str:
        return f'{self.recordType} {self.name}: {self.value}'

    # get the expiry timestamp of this record
    @property
    def expiry(self) -> float:
        if self.ttl < 0: return float('inf') # no expiry
        else: return self.queriedAt + self.ttl
    
    # whether the record has expired
    @property
    def expired(self) -> bool:
        return self.expiry < time()

    # convert from record name to raw name data
    @staticmethod
    def convertRecordName(name: str) -> bytes:
        labels = name.split('.')
        result = bytearray()
        for label in labels: # add labels into the field
            result.extend(pack('B', len(label))) # label length
            result.extend(label.encode()) # then the label itself
        result.append(0) # termination
        return result

    # name field
    @property
    def nameField(self) -> bytes:
        return Record.convertRecordName(self.name)
    
    # record type IDs (https://en.wikipedia.org/wiki/List_of_DNS_record_types)
    # while we only use A, NS and CNAME, we probably should implement them all
    RECORD_TYPES = {
        # common types
        'A': 1, 'AAAA': 28, 'AFSDB': 18, 'APL': 42, 'CAA': 257, 'CDNSKEY': 60,
        'CDS': 59, 'CERT': 37, 'CNAME': 5, 'CSYNC': 62, 'DHCID': 49, 'DLV': 32769,
        'DNAME': 39, 'DNSKEY': 48, 'DS': 43, 'EUI48': 108, 'EUI64': 109, 'HINFO': 13,
        'HIP': 55, 'HTTPS': 65, 'IPSECKEY': 45, 'KEY': 25, 'KX': 36, 'LOC': 29, 'MX': 15,
        'NAPTR': 35, 'NS': 2, 'NSEC': 47, 'NSEC3': 50, 'NSEC3PARAM': 51, 'OPENPGPKEY': 61,
        'PTR': 12, 'RP': 17, 'RRSIG': 46, 'SIG': 24, 'SMIMEA': 53, 'SOA': 6, 'SRV': 33,
        'SSHFP': 44, 'SVCB': 64, 'TA': 32768, 'TKEY': 249, 'TLSA': 52, 'TSIG': 250, 'TXT': 16,
        'URI': 256, 'ZONEMD': 63,

        # pseudo-RR
        '*': 255, 'AXFR': 252, 'IXFR': 251, 'OPT': 41,

        # obsolete types
        'MD': 3, 'MF': 4, 'MAILA': 254, 'MB': 7, 'MG': 8, 'MR': 9, 'MINFO': 14, 'MAILB': 253,
        'WKS': 11, 'NB': 32, 'NBSTAT': 33, 'NULL': 10, 'A6': 38, 'NXT': 30, 'X25': 19, 'ISDN': 20,
        'RT': 21, 'NSAP': 22, 'NSAP-PTR': 23, 'PX': 26, 'EID': 31, 'NIMLOC': 32, 'ATMA': 34, 'APL': 42,
        'SINK': 40, 'GPOS': 27, 'UINFO': 100, 'UID': 101, 'GID': 102, 'UNSPEC': 103, 'SPF': 99,
        'NINFO': 56, 'RKEY': 57, 'TALINK': 58, 'NID': 104, 'L32': 105, 'L64': 106, 'LP': 107, 'DOA': 259
    }

    # record type field
    @property
    def typeField(self) -> bytes:
        return pack('!H', Record.RECORD_TYPES[self.recordType])

    # class code field (always returns the value for IN)
    @property
    def classField(self) -> bytes:
        return pack('!H', 0x0001)

    # question record
    @property
    def question(self) -> bytes:
        result = bytearray() # bytearray for the question

        result.extend(self.nameField) # get name field (always uncompressed)
        result.extend(self.typeField) # then record type (2 bytes)
        result.extend(self.classField) # class code

        return result
    
    # TTL field
    @property
    def ttlField(self) -> bytes:
        return pack('!L', self.ttl if self.ttl > 0 else 0x7FFFFFFF) # maximum TTL is 2^31 - 1 sec

    # answer record
    @property
    def answer(self) -> bytes:
        result = bytearray() # bytearray for the answer

        result.extend(self.nameField) # we don't do compressed names on our end, since that's kind of evil (and not really needed either)
        result.extend(self.typeField)
        result.extend(self.classField)
        result.extend(self.ttlField)

        if self.recordType == 'A': # IPv4 address - convert from string notation to raw data
            data = bytearray([int(x) for x in self.value.split('.')])
        elif self.recordType == 'AAAA': # IPv6 address
            data = bytearray.fromhex(self.value.replace(':', '')) # remove all separators, then convert to hex bytearray
        elif self.recordType == 'CNAME' or self.recordType == 'NS': # TODO: add any other record type that returns label
            data = Record.convertRecordName(self.value)
        else:
            data = self.value.encode('ascii')
        result.extend(pack('!H', len(data))) # RDLENGTH
        result.extend(data) # RDATA

        return result

    # decode name from RR
    @staticmethod
    def nameFromRR(rr: bytes, msg: bytes | None = None) -> tuple[int, str]:
        index = 0 # index into RR
        
        name = ''
        while rr[index] != 0:
            labelLength = rr[index]

            if labelLength & 0xC0 != 0: # name compression                
                if msg is None: # no message to decompress name
                    index += 1
                    break

                offset = unpack('!H', rr[index:index+2])[0] & ~0xC000 # get message offset, from which we extract the name
                _, decompressedName = Record.nameFromRR(msg[offset:], msg)
                name += decompressedName + '.'
                index += 1
                break

            index += 1
            name += rr[index:index+labelLength].decode() + '.' # add dot for next label
            index += labelLength
        name = name.removesuffix('.') # remove last dot
        index += 1 # skip past the zero that triggered the end of the while loop above

        return (index, name)

    # search for record type string
    @staticmethod
    def getType(id: int) -> str | None:
        for rType, rID in Record.RECORD_TYPES.items():
            if rID == id: return rType
        
        return None

    # decode from question buffer
    @staticmethod
    def fromQuestion(question: bytes) -> tuple[int, Self]: # returns number of bytes read, as well as the record in question
        nameLength, name = Record.nameFromRR(question) # decode name - the name must be uncompressed
        recordType = Record.getType(unpack('!H', question[nameLength:nameLength+2])[0]) # decode record type
        # ignore class code

        return (nameLength + 4, Record(recordType, name))
    
    # decode from answer buffer
    @staticmethod
    def fromAnswer(answer: bytes, msg: bytes | None = None) -> tuple[int, Self]: # returns number of bytes read, as well as the record
        nameLength, name = Record.nameFromRR(answer, msg) # decode name (decompression might be performed here, so it's highly recommended that msg is provided)
        recordType = Record.getType(unpack('!H', answer[nameLength:nameLength+2])[0]) # decode record type
        # ignore class code
        ttl = unpack('!L', answer[nameLength+4:nameLength+8])[0]

        # read data 
        rdLength = unpack('!H', answer[nameLength+8:nameLength+10])[0]
        rdStart = nameLength + 10
        if recordType == 'A': # A record
            value = '.'.join([str(x) for x in unpack('BBBB', answer[rdStart:rdStart+4])]) # IP address to string
        elif recordType == 'AAAA': # AAAA record (IPv6) - got no use for us
            value = ':'.join([f'{x:04x}' for x in unpack('!HHHHHHHH', answer[rdStart:rdStart+16])]) # IPv6 address to string
        elif recordType == 'CNAME' or recordType == 'NS':
            _, value = Record.nameFromRR(answer[rdStart:rdStart+rdLength], msg) # decode CNAME/NS to string
        else:
            value = answer[rdStart:rdStart+rdLength].decode('ascii')

        return (rdStart + rdLength, Record(recordType, name, value, ttl))       


# DNS message class
class DNSMessage:
    # list of response codes
    RESP_CODES = {
        'NOERROR': 0,
        'FORMERR': 1,
        'SERVFAIL': 2,
        'NXDOMAIN': 3,
        'NOTIMP': 4,
        'REFUSED': 5,
        'YXDOMAIN': 6,
        'YXRRSET': 7,
        'NXRRSET': 8,
        'NOTAUTH': 9,
        'NOTZONE': 10,
        'DSOTYPENI': 11,
        'BADVERS': 16,
        'BADSIG': 16,
        'BADKEY': 17,
        'BADTIME': 18,
        'BADMODE': 19,
        'BADNAME': 20,
        'BADALG': 21,
        'BADTRUNC': 22,
        'BADCOOKIE': 23
    }

    # get response code string from ID
    @staticmethod
    def getResponseCode(id: int) -> str:
        for rType, rID in DNSMessage.RESP_CODES.items():
            if rID == id: return rType
        
        return None

    def __init__(
            self,
            id=None,
            respCode: str | None = None, # None for questions
            recurseDesired=False,
            recurseAvailable=False,
            questions: list[Record] = [],
            answers: list[Record] = [],
            authority: list[Record] = [],
            additional: list[Record] = []
    ):
        self.id = id if id is not None else randint(0, 65535) # generate a random ID if it's not provided
        self.respCode = respCode
        self.recurseDesired = recurseDesired
        self.recurseAvailable = recurseAvailable
        self.questions = questions
        self.answers = answers
        self.authority = authority
        self.additional = additional
    
    # check if there's an error (that is not NXDOMAIN)
    @property
    def error(self) -> bool:
        return not (self.respCode == 'NOERROR' or self.respCode == 'NXDOMAIN')

    # decode questions field
    @staticmethod
    def decodeQuestions(questions: bytes, numQuestions: int) -> tuple[int, list[Record]]: # returns number of bytes read and the record list
        result = []
        index = 0 # index into questions
        for i in range(numQuestions):
            entryLength, record = Record.fromQuestion(questions[index:])
            index += entryLength # advance index
            result.append(record) # add record to list
        return (index, result)
    
    # decode responses field
    @staticmethod
    def decodeResponses(responses: bytes, numResponses: int, msg: bytes | None = None) -> tuple[int, list[Record]]: # same as above
        result = []
        index = 0 # index into responses
        for i in range(numResponses):
            entryLength, record = Record.fromAnswer(responses[index:], msg)
            index += entryLength # advance index
            result.append(record) # add record to list
        return (index, result)
    
    # encode questions field
    @staticmethod
    def encodeQuestions(questions: list[Record]) -> bytes:
        result = bytearray()
        for entry in questions:
            result.extend(entry.question)
        return result
    
    # encode responses field
    @staticmethod
    def encodeResponses(responses: list[Record]) -> bytes:
        result = bytearray()
        for entry in responses:
            result.extend(entry.answer)
        return result

    # create DNSMessage object from raw DNS message
    @staticmethod
    def fromMessage(msg: bytes) -> Self:
        # parse header
        id, flagsRC = unpack('!HH', msg[0:4]) # transaction ID, as well as flags and RCODE
        reply = flagsRC & (1 << 15) != 0 # set if this is a response
        rcode = flagsRC & 0b1111 # last 4 bits of flagsRC is the response code (only valid if reply = True)
        rd = flagsRC & (1 << 8) != 0 # recursion desired
        ra = flagsRC & (1 << 7) != 0 # recursion available
        numQuestions, numAnswers, numAuthorities, numAdditional = unpack('!HHHH', msg[4:12]) # counts

        # decode RRs
        entryStart = 12 # start of entry we're decoding
        size, questions = DNSMessage.decodeQuestions(msg[entryStart:], numQuestions); entryStart += size
        size, answers = DNSMessage.decodeResponses(msg[entryStart:], numAnswers, msg); entryStart += size
        size, authorities = DNSMessage.decodeResponses(msg[entryStart:], numAuthorities, msg); entryStart += size
        size, additional = DNSMessage.decodeResponses(msg[entryStart:], numAdditional, msg); entryStart += size

        return DNSMessage(id, DNSMessage.getResponseCode(rcode) if reply else None, rd, ra, questions, answers, authorities, additional) # intiailise message object from extracted information
    
    # output raw DNS message
    @property
    def payload(self) -> bytes:
        result = bytearray() # buffer to hold payload as we build it

        result.extend(pack('!H', self.id)) # transaction ID
        
        # build flag
        flagsRC = 0
        if self.recurseAvailable: flagsRC |= 1 << 7
        if self.recurseDesired: flagsRC |= 1 << 8
        if self.respCode is not None: flagsRC |= DNSMessage.RESP_CODES[self.respCode] | (1 << 15) # response message - set QR=1 and add response code
        result.extend(pack('!H', flagsRC))

        # add entry counts
        result.extend(pack('!HHHH', len(self.questions), len(self.answers), len(self.authority), len(self.additional)))

        # add entries
        result.extend(DNSMessage.encodeQuestions(self.questions))
        result.extend(DNSMessage.encodeResponses(self.answers))
        result.extend(DNSMessage.encodeResponses(self.authority))
        result.extend(DNSMessage.encodeResponses(self.additional))

        return result

# class for a DNS zone (e.g. example.com or au)
class Zone:
    def __init__(self, subzones: dict[str, Self] | None = None, records: list[Record] | None = None, ttl: int | None = None, queriedAt: float | None = None):
        self.subzones: dict[str, Zone] = subzones if subzones is not None else {} # child zones under this zone, with key being the subzone's name excluding its parent (e.g. example)
        self.records: list[Record] = records if records is not None else [] # DNS records associated with this subzone - this cannot be stored as a key-value pair since a domain may have multiple records of the same type (e.g. A record for multiple servers handling the website)
        self.ttl: int = ttl if ttl is not None else -1 # time-to-live of this zone (as it might be queried from a DNS server upstream, which might set its NS record's TTL) - -1 means no TTL
        self.queriedAt: float = queriedAt if queriedAt is not None else time() # timestamp of when the zone was queried from the upstream DNS server and saved in our cache

    # get the expiry timestamp of the zone
    @property
    def expiry(self) -> float:
        if self.ttl < 0: return float('inf') # no expiry
        else: return self.queriedAt + self.ttl
    
    # whether the zone has expired
    @property
    def expired(self) -> bool:
        return self.expiry < time()

    # get the closest matching zone object for a given subzone path (e.g. example.com -> [example, com])
    def getZone(self, path: list[str]) -> tuple[list[str], Self]:
        if len(path) == 0: return (path, self) # return ourselves if the path is empty (so we can make getZone recursive)
        
        # recursively find the zone object by querying for the object corresponding to the next zone level and passing the remaining query onto it
        # for example, a query for www.example.com ([www, example, com] is done by passing [www, example] to the com subzone,
        # which will in turn pass [www] to the example.com subzone, which will then pass [] to the www.example.com subzone, which will return itself
        nextZone = path[-1] # next zone - we should have a zone saved for this
        if nextZone in self.subzones: # we do have the object corresponding to this zone
            nextZoneObject = self.subzones[nextZone]
            if nextZoneObject.expired: # zone has expired
                self.subzones.remove(nextZoneObject)
            else:
                path, zone = nextZoneObject.getZone(path[:-1]) # send the path minus nextZone on to the next zone for search
                path.append(nextZone) # add nextZone back into the path
                return (path, zone) # before returning
        
        # we don't have the object - we'll stop with ourselves
        return ([], self) # the caller is responsible for adding any stripped zones back in before returning to the user
    
    # get all records of a given type
    def getRecords(self, recordType: str) -> list[Record]:
        records = [] # records that we'll return
        recordsToRemove = [] # list of records to remove due to expiry - this method also pulls double duty
        
        for record in self.records:
            if record.expired: # expired record encountered
                recordsToRemove.append(record)
                continue # move on to next one
        
            if record.recordType == recordType: # matches requested type, and is not expired
                records.append(record)
        
        for record in recordsToRemove:
            self.records.remove(record) # remove expired records that we've just found - this frees up memory
        
        return records

# root zone
rootZone: Zone = Zone(
    subzones={
        'net': Zone(
            subzones={
                'root-servers': Zone(
                    subzones={
                        k: Zone(records=[Record('A', f'{k}.root-servers.net', v)])
                        for k, v in {
                            'a': '198.41.0.4',
                            'b': '170.247.170.2',
                            'c': '192.33.4.12',
                            'd': '199.7.91.13',
                            'e': '192.203.230.10',
                            'f': '192.5.5.241',
                            'g': '192.112.36.4',
                            'h': '198.97.190.53',
                            'i': '192.36.148.17',
                            'j': '192.58.128.30',
                            'k': '193.0.14.129',
                            'l': '199.7.83.42',
                            'm': '202.12.27.33'
                        }.items() # from https://www.iana.org/domains/root/servers
                    },
                    records=[Record('NS', 'root-servers.net', f'{x}.root-servers.net') for x in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm']] # retrieved from DiG: dig NS root-servers.net. we also have the A records for those name servers defined here, so we should be fine
                )
            }
            # NOTE: we'll need to populate the .net nameservers - the root server hint is good enough for bootstrapping
        )
        # NOTE: it might also be a good idea to populate other gTLDs' NS records
    },
    records=[Record('NS', '', f'{x}.root-servers.net') for x in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm']] # root DNS servers: https://www.iana.org/domains/root/servers
)

# create DNS client socket so we can make DNS queries too

# add DNS records to our cache
def addRecords(records: list[Record]):
    # sort records by zone, so we can batch insert records
    recordsByZone: dict[tuple[str], list[Record]] = {} # lists are unhashable, so we have to use tuples here
    for record in records:
        if record.recordType != 'A' and record.recordType != 'CNAME' and record.recordType != 'NS': continue # we're not interested in records that are not A, CNAME or NS
        path = tuple(record.name.split('.')) # get the path for this record
        if path not in recordsByZone: recordsByZone[path] = [] # initialise records list if it's not there yet
        recordsByZone[path].append(record) # then add record into group
    
    for path in recordsByZone:
        closestPath, zone = rootZone.getZone(list(path)) # try to find the closest zone
        if len(closestPath) < len(path): # we haven't got the zone object yet, so we'll need to create it
            for zoneIndex in range(len(path) - len(closestPath) - 1, -1, -1): # go from the zone immediately adjacent to the closest zone, down to the child-most one
                closestZone = zone
                zone = Zone() # create new zone
                closestZone.subzones[path[zoneIndex]] = zone # then add it to the closest zone
        
        zone.records.extend(recordsByZone[path]) # batch insert records that we've sorted above

client = socket(AF_INET, SOCK_DGRAM) # client socket, to be used for upstream DNS queries

# query for a DNS record, using local cache and (if recursive) upstream DNS queries
def queryRecord(recordType: str, name: str, recursive: bool) -> tuple[list[Record], list[Record]] | None: # will return ([], []) if the domain cannot be found at all, or None if there's an error with the upstream DNS server
    print(f'Querying {recordType} {name} ({"recursive" if recursive else "iterative"})')
    
    nonAuthoritativeAnswers: list[Record] = [] # list of non-authoritative answers to return
    additionalAnswers: list[Record] = [] # list of additional answers to return

    zonePath = name.split('.') # split the requested domain into path (so we can pass into the root zone's getZone method)

    closestPath, closestZone = rootZone.getZone(zonePath) # query for the closest zone and its path that we already have in the cache

    while True: # localQueryEval
        if len(closestPath) == len(zonePath): # we managed to get all the way to the desired domain
            records = closestZone.getRecords(recordType) # attempt to get all of the requested records
            if len(records) > 0: # we have the requested record, which we can serve straight away
                nonAuthoritativeAnswers = records # all answers from this DNS server will be non-authoritative
                break # exit localQueryEval (and return)
            else:
                records = closestZone.getRecords('CNAME') # attempt to get CNAME record
                if len(records) > 0: # we have a CNAME record (by specification, there can only be one of them)
                    nonAuthoritativeAnswers = records # return CNAME to client - the DNS query restart is to be performed on the client side, and never ours
                    break
                # otherwise, we don't have any of the requested record for this domain - but we might have an NS record

        # handleNSRecords - we'll get here if len(closestPath) != len(zonePath), or if we don't have any of the requested record
        records = []
        while True: # continue going down until we can find a zone that has NS records
            records = closestZone.getRecords('NS') # attempt to get NS records
            if len(records) > 0: break # there are NS records in this zone

            closestPath, closestZone = rootZone.getZone(closestPath[1:]) # get the parent zone (and set closestPath)
        
        # otherwise, we do have NS records that we can try
        if recursive: # recursive query
            # query NS record servers, and save them in cache. note that we have multiple options here, so we can simply try another server if we cannot get a response
            for nsRecord in records: # iterate through NS records to try each one of them
                recNAAnswers, _ = queryRecord('A', nsRecord.value, False) # get the A record for this nameserver (which we can assume that we already have, since that's returned by upstream nameservers in additional answers)
                if len(recNAAnswers) == 0: # we've hit a dead end - terminate here
                    return ([], [])
                for nsARecord in recNAAnswers: # iterate through possible IP addresses until we can get a response
                    # ask for our full zone with no recursion - the root-most nameserver will return the next immediate zone
                    print(f'Making upstream DNS query to {nsARecord.value} ({nsRecord.value}): {recordType} {name}')
                    client.sendto(DNSMessage(recurseDesired=False, questions=[Record(recordType, name)]).payload, (nsARecord.value, 53))
                    rawResponse, _ = client.recvfrom(BUFFER_SIZE)
                    response: DNSMessage = DNSMessage.fromMessage(rawResponse) # decode DNS message from server

                    if response.error: continue # if there's an error (that is not NXDOMAIN), we try the next one
                    if response.respCode == 'NXDOMAIN': # nameserver said that the domain definitely doesn't exist - return immediately (this is what DiG does)
                        return ([], [])
                    
                    # add all answers that we've got (including authoritative, non-authoritative, and additional). additional answers are especially important here, since they usually contain the A records for the nameservers given in the NS records
                    addRecords(response.answers)
                    addRecords(response.authority)
                    addRecords(response.additional)

                    return queryRecord(recordType, name, recursive) # try querying again, now that we're one step further (we can optimise this further, but it will complicate the code)
                # if we get here, we have to try another NS record (otherwise we would've returned - see above)            
            return None # we cannot query any upstream DNS server
        else: # iterative query - return NS records straight away, and the querying application must query the NS records by themselves
            nonAuthoritativeAnswers = records
            for record in records: # go through NS records and add their A records into additional answers
                # however, we should only add A records that we already have
                recordPath = record.value.split('.')
                closestPath, closestZone = rootZone.getZone(recordPath)
                if len(closestPath) < len(recordPath): continue # we don't even have the zone - skip
                additionalAnswers.extend(closestZone.getRecords('A')) # query for all A records belonging to the NS record's zone and add them to additional answers
        
        break # exit from the while loop

    return (nonAuthoritativeAnswers, additionalAnswers)

def main():
    # initialise DNS zone cache
    for tld in ['com', 'org', 'net', 'edu', 'gov', 'mil']: # initialise gTLD DNS zones and their nameservers (at least .net must be initialised)
        print(f'Prefetching NS records for {tld} TLD.')
        queryRecord('NS', tld, True) # has to be recursive, so that the root DNS servers would get queried

    with socket(AF_INET, SOCK_DGRAM) as server:
        server.bind((SERVER_ADDR, SERVER_PORT))

        print(f'DNS server is active on {SERVER_ADDR}:{SERVER_PORT}')
        while True:
            rawQuery, clientAddr = server.recvfrom(BUFFER_SIZE)
            query: DNSMessage = DNSMessage.fromMessage(rawQuery)
            query.recurseAvailable = True # let client know that we can do recursive queries too

            for question in query.questions:
                print(f'Answering {clientAddr} {"recursive" if query.recurseDesired else "iterative"} DNS query: {question.recordType} {question.name}')
                
                result = queryRecord(question.recordType, question.name, query.recurseDesired)
                if result is None:
                    print(f'Error encountered from upstream DNS server')
                    query.respCode = 'SERVFAIL'
                    break # abort now

                nonAuthoritativeAnswers, additionalAnswers = result # unpack answers
                query.answers.extend(nonAuthoritativeAnswers)
                query.additional.extend(additionalAnswers)

            print(f'Responding to {clientAddr} (transaction ID 0x{query.id:04X}).')
            query.respCode = 'NOERROR'
            client.sendto(query.payload, clientAddr) # encode and reply to client

if __name__ == '__main__':
    main()
