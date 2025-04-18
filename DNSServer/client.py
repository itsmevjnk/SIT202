from socket import *
from struct import pack, unpack
from time import time
from random import randint
from os import getenv

from typing_extensions import Self

BUFFER_SIZE = 2048 # buffer size for receiving UDP datagrams
DNS_PORT = int(getenv('PORT', '53')) # DNS port number - use PORT=10053 python3 client.py to connect to our server

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

def printRecords(records: list[Record], printValue: bool = True):
    for record in records:
        print(f' - {record.name}, type {record.recordType}', end='')
        if printValue:
            print(f': {record.value} (TTL={record.ttl if record.ttl >= 0 else "infinity"})')
        else: print() # new line

def main():
    # prompt for DNS server address
    serverAddress = input('Please enter the DNS server address: ')

    with socket(AF_INET, SOCK_DGRAM) as client:
        while True:
            print(f'\nUsing DNS server on {serverAddress} (port {DNS_PORT})')

            # prompt for hostname
            hostname = input('Please enter the hostname to query: ')
            if len(hostname) == 0:
                print('Empty hostname provided')
                continue # go back immediately if an empty hostname is provided

            # prompt for record type (A, CNAME, NS)
            recordType = input('Please enter the record type to query (A, CNAME or NS): ').upper()
            if recordType not in ['A', 'CNAME', 'NS']:
                print('Invalid of unsupported record type')
                continue

            # ask if recursive query is desired
            recurse = True
            choice = input(f'Do you want to query recursively? (Y/n) ').lower()
            if choice == 'n': recurse = False # recursive by default

            print('Sending DNS query.')
            client.sendto(DNSMessage(recurseDesired=recurse, questions=[Record(recordType, hostname)]).payload, (serverAddress, DNS_PORT)) # create DNS message, encode it, then send it to serverAddress on port 53 (DNS)

            print('Receiving DNS response.')
            rawResponse, _ = client.recvfrom(BUFFER_SIZE)
            responseMsg: DNSMessage = DNSMessage.fromMessage(rawResponse) # decode DNS message from server
            print(f'DNS response: {responseMsg.respCode}, ID {responseMsg.id}, recursion available: {responseMsg.recurseAvailable}')
            print(f'Non-authoritative answers: {len(responseMsg.answers)}'); printRecords(responseMsg.answers)
            print(f'Authoritative answers: {len(responseMsg.authority)}'); printRecords(responseMsg.authority)
            print(f'Additional answers: {len(responseMsg.additional)}'); printRecords(responseMsg.additional)
            

            # ask if the user wants to exit
            choice = input(f'Do you want to continue with another DNS query? (Y/n) ').lower()
            if choice == 'n': break # continue by default
        
        print('\nExiting.')

if __name__ == '__main__':
    main()
