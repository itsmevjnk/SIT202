# 5.2C - My DNS Server Sketch
# The following Python-like pseudocode outlines the logical flow design of a DNS server
# capable of handling A and CNAME records.
# This logic flow was built from information from Module 2, as well as the behaviour of
# the DiG and nslookup utilities as captured by Wireshark.

# class for a DNS record
class Record:
    def __init__(self, recordType: str, name: str, value: str, ttl: int):
        self.recordType = recordType # record type (A/CNAME/NS)
        self.name = name # the record's name (e.g. example.com)
        self.value = value # the record's value
        self.ttl = ttl # the record's TTL (< 0 means no expiry)
        self.queriedAt: timestamp = currentTime() # timestamp of when this record was queried from the upstream DNS server
    
    # get the expiry timestamp of this record
    def getExpiry(self) -> timestamp:
        if self.ttl < 0: return timestamp.MAX # no expiry
        else: return self.queriedAt + self.ttl

# class for a DNS zone (e.g. example.com or au)
class Zone:
    def __init__(self):
        self.subzones: dict[str, Zone] = {} # child zones under this zone, with key being the subzone's name excluding its parent (e.g. example)
        self.records: list[Record] = [] # DNS records associated with this subzone - this cannot be stored as a key-value pair since a domain may have multiple records of the same type (e.g. A record for multiple servers handling the website)
        self.ttl: int = -1 # time-to-live of this zone (as it might be queried from a DNS server upstream, which might set its NS record's TTL) - -1 means no TTL
        self.queriedAt: timestamp = currentTime() # timestamp of when the zone was queried from the upstream DNS server and saved in our cache

    # get the expiry timestamp of the zone
    def getExpiry(self) -> timestamp:
        if self.ttl < 0: return timestamp.MAX # no expiry
        else: return self.queriedAt + self.ttl

    # get the closest matching zone object for a given subzone path (e.g. example.com -> [example, com])
    def getZone(path: list[str]) -> tuple[list[str], Zone]:
        if len(path) == 0: return (path, self) # return ourselves if the path is empty (so we can make getZone recursive)
        
        # recursively find the zone object by querying for the object corresponding to the next zone level and passing the remaining query onto it
        # for example, a query for www.example.com ([www, example, com] is done by passing [www, example] to the com subzone,
        # which will in turn pass [www] to the example.com subzone, which will then pass [] to the www.example.com subzone, which will return itself
        nextZone = path[-1] # next zone - we should have a zone saved for this
        if nextZone in self.subzones: # we do have the object corresponding to this zone
            nextZoneObject = self.subzones[nextZone]
            if nextZoneObject.getExpiry() < currentTime(): # zone has expired
                self.subzones.remove(nextZoneObject)
            else:
                path, zone = nextZoneObject.getZone(path[:-1]) # send the path minus nextZone on to the next zone for search
                path.append(nextZone) # add nextZone back into the path
                return (path, zone) # before returning
        
        # we don't have the object - we'll stop with ourselves
        return ([], self) # the caller is responsible for adding any stripped zones back in before returning to the user
    
    # get all records of a given type
    def getRecords(recordType: str) -> list[Record]:
        records = [] # records that we'll return
        recordsToRemove = [] # list of records to remove due to expiry - this method also pulls double duty
        
        for record in self.records:
            if record.getExpiry() < currentTime(): # expired record encountered
                recordsToRemove.append(record)
                continue # move on to next one
        
            if record.recordType == recordType: # matches requested type, and is not expired
                records.append(record)
        
        for record in recordsToRemove:
            self.records.remove(record) # remove expired records that we've just found - this frees up memory
        
        return records

rootZone: Zone = loadRootZone() # load root zone (which is a Zone object above) from an external source (e.g. config file), or we can initialise it within the program too

# create DNS client socket so we can make DNS queries too
client = createSocket(UDP)

# add DNS records to our cache
def addRecords(records: list[Records]):
    # sort records by zone, so we can batch insert records
    recordsByZone: dict[list[str], list[Records]] = {}
    for record in records:
        if record.recordType != 'A' and record.recordType != 'CNAME' and record.recordType != 'NS': continue # we're not interested in records that are not A, CNAME or NS
        path = record.name.split('.') # get the path for this record
        if path not in recordsByZone: recordsByZone[path] = [] # initialise records list if it's not there yet
        recordsByZone[path].append(record) # then add record into group
    
    for path in recordsByZone:
        closestPath, zone = rootZone.getZone(path) # try to find the closest zone
        if len(closestPath) < len(path): # we haven't got the zone object yet, so we'll need to create it
            for zoneIndex in range(len(path) - len(closestPath) - 1, -1, -1): # go from the zone immediately adjacent to the closest zone, down to the child-most one
                closestZone = zone
                zone = Zone() # create new zone
                closestZone.subzones[path[zoneIndex]] = zone # then add it to the closest zone
        
        zone.records.extend(recordsByZone[record]) # batch insert records that we've sorted above

# query for a DNS record, using local cache and (if recursive) upstream DNS queries
def queryRecord(recordType: str, name: str, recursive: bool) -> tuple[list[Record], list[Record]] | None: # will return ([], []) if the domain cannot be found at all, or None if there's an error with the upstream DNS server
    nonAuthoritativeAnswers: list[Record] = [] # list of non-authoritative answers to return
    additionalAnswers: list[Record] = [] # list of additional answers to return

    zonePath = name.split('.') # split the requested domain into path (so we can pass into the root zone's getZone method)

    closestPath, closestZone = rootZone.getZone(zonePath) # query for the closest zone and its path that we already have in the cache
[localQueryEval]:
    if len(closestPath) == len(zonePath): # we managed to get all the way to the desired domain
        records = closestZone.getRecords(recordType) # attempt to get all of the requested records
        if len(records) > 0: # we have the requested record, which we can serve straight away
            nonAuthoritativeAnswers = records # all answers from this DNS server will be non-authoritative
        else:
            records = closestZone.getRecords('CNAME') # attempt to get CNAME record
            if len(records) > 0: # we have a CNAME record (by specification, there can only be one of them)
                nonAuthoritativeAnswers = records # return CNAME to client - the DNS query restart is to be performed on the client side, and never ours
            else: # we don't have any of the requested record for this domain - but we might have an NS record
                goto handleNSRecords # the logic is implemented below
    else: # we cannot get that far - we'll need to base off NS records
[handleNSRecords]:
        records = closestZone.getRecords('NS') # attempt to get NS records
        if len(records) == 0: # we don't have NS
            closestPath, parentZone = rootZone.getZone(zonePath[1:]) # get the parent zone (and set closestPath)
            closestZone = parentZone # go one step back
            goto localQueryEval # so we don't have to re-query for the parent internally
        
        # otherwise, we do have NS records that we can try
        if recursive: # recursive query
            # TODO: query NS record servers, and save them in cache. note that we have multiple options here, so we can simply try another server if we cannot get a response
            nsRecords = records # as we'll be reusing the name here
            gotRecord = False # set when we've got the next step for our record
            for nsRecord in nsRecords: # iterate through NS records to try each one of them
                recNAAnswers, _ = queryRecord('A', nsRecord.name, False) # get the A record for this nameserver (which we can assume that we already have, since that's returned by upstream nameservers in additional answers)
                if len(recNAAnswers) == 0: # we've hit a dead end - terminate here
                    return ([], [])
                for nsARecord in recNAAnswers: # iterate through possible IP addresses until we can get a response
                    response = client.sendQuery(nsARecord.value, recordType, name, False) # ask for our full zone with no recursion - the root-most nameserver will return the next immediate zone
                    if response.error: continue # if there's an error (that is not NXDOMAIN), we try the next one
                    if response.replyCode == NXDOMAIN: # nameserver said that the domain definitely doesn't exist - return immediately (this is what DiG does)
                        return ([], [])
                    gotRecord = True # so that we can exit
                    addRecords(response.allAnswers) # add all answers that we've got (including authoritative, non-authoritative, and additional). additional answers are especially important here, since they usually contain the A records for the nameservers given in the NS records
                    return queryRecord(recordType, name, recursive) # try querying again, now that we're one step further (we can optimise this further, but it will complicate the code)
                # if we get here, we have to try another NS record (otherwise we would've returned - see above)            
            return None # we cannot query any upstream DNS server
        else: # iterative query - return NS records straight away, and the querying application must query the NS records by themselves
            nonAuthoritativeAnswers = records
            for record in records: # go through NS records and add their A records into additional answers
                additionalAnswers.extend(queryRecord('A', record.value, False)

    return (nonAuthoritativeAnswers, additionalAnswers)

# set up UDP socket and bind to port 53 (DNS)
server = createSocket(UDP)
server.bind(53)

while True: # loop forever to receive DNS queries and respond to them
    query, clientAddress = server.receiveQuery() # we assume that the DNS query has been decoded
    recursive = query.flags.RD # Recursive Desired flag - indicates whether we should do an iterative or recursive query
    query.flags.RA = recursive # duplicate recursive option into Recursive Available, since we'll do a recursive query if we're told to
    
    for question in query.questions: # iterate through all the DNS questions
        result = queryRecord(question.recordType, question.name, recursive) # find the result for each question from our cache (and if recursive=True, from upstream DNS servers too)
        if result is None: # error from upstream DNS server
            query.replyCode = SERVFAIL # indicate server failure
            break # abort now - so we can send response
            
        nonAuthoritativeAnswers, additionalAnswers = result # unpack answers
        query.addNonAuthoritativeAnswers(nonAuthoritativeAnswers) # then add them to response
        query.addAdditionalAnswers(additionalAnswers)
                
    server.sendQueryResponse(clientAddress, query) # we can reuse the DNS query format for DNS response
