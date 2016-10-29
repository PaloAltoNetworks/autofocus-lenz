#!/usr/bin/env python
from inspect import isfunction
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = ""
from autofocus import AFSession, AFSample
from autofocus import AFServiceActivity, AFRegistryActivity, AFProcessActivity, AFApiActivity, AFJavaApiActivity, AFUserAgentFragment, AFMutexActivity, AFHttpActivity, AFDnsActivity, AFBehaviorTypeAnalysis, AFBehaviorAnalysis, AFConnectionActivity, AFFileActivity
# APK Specific
from autofocus import AFApkActivityAnalysis, AFApkIntentFilterAnalysis, AFApkReceiverAnalysis, AFApkSensorAnalysis, AFApkServiceAnalysis, AFApkEmbededUrlAnalysis, AFApkRequestedPermissionAnalysis, AFApkSensitiveApiCallAnalysis, AFApkSuspiciousApiCallAnalysis, AFApkSuspiciousFileAnalysis, AFApkSuspiciousStringAnalysis
import sys, argparse, multiprocessing, os, re

__author__  = "Jeff White [karttoon]"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.1.7"
__date__    = "11OCT2016"

#######################
# Check research mode #
#######################

research_mode = "False"

try:
    import ConfigParser
    parser      = ConfigParser.ConfigParser()
    conf_path   = os.environ.get("PANW_CONFIG", "~/.config/panw")
    parser.read(os.path.expanduser(conf_path))
    research_mode = parser.get("researcher", "enabled")
except:
    pass

####################
# Build structures #
####################

def build_field_list():

    field_list = {
        "service"           : [],
        "registry"          : [],
        "process"           : [],
        "japi"              : [],
        "misc"              : [],
        "user_agent"        : [],
        "mutex"             : [],
        "http"              : [],
        "dns"               : [],
        "behavior_desc"     : [],
        "behavior_type"     : [],
        "connection"        : [],
        "file"              : [],
        "apk_misc"          : [],
        "apk_filter"        : [],
        "apk_receiver"      : [],
        "apk_sensor"        : [],
        "apk_service"       : [],
        "apk_embedurl"      : [],
        "apk_permission"    : [],
        "apk_sensitiveapi"  : [],
        "apk_suspiciousapi" : [],
        "apk_file"          : [],
        "apk_string"        : [],
        "digital_signer"    : [],
        "imphash"           : [],
        "default"           : []
    }

    return field_list

def build_field_dict():

    field_dict = {
        "service"           :{},
        "registry"          :{},
        "process"           :{},
        "japi"              :{},
        "misc"              :{},
        "user_agent"        :{},
        "mutex"             :{},
        "http"              :{},
        "dns"               :{},
        "behavior_desc"     :{},
        "behavior_type"     :{},
        "connection"        :{},
        "file"              :{},
        "apk_misc"          :{},
        "apk_filter"        :{},
        "apk_receiver"      :{},
        "apk_sensor"        :{},
        "apk_service"       :{},
        "apk_embedurl"      :{},
        "apk_permission"    :{},
        "apk_sensitiveapi"  :{},
        "apk_suspiciousapi" :{},
        "apk_file"          :{},
        "apk_string"        :{},
        "digital_signer"    :{},
        "imphash"           :{},
        "default"           :{}
    }

    return field_dict

def build_session_list():

    session_list = {
        "email_subject"     :[],
        "file_name"         :[],
        "application"       :[],
        "dst_country"       :[],
        "industry"          :[],
        "email_sender"      :[],
        "file_url"          :[],
        "email_recipient"   :[],
        "account_name"      :[]
    }

    return session_list

##########################
# AF QUERY SECTION BELOW #
##########################

# Af Query Function
# Takes a type of query and the query itself as input.  Example: af_query("hash",<sha256 hash>)
# Returns a properly formatted autofocus query to be passed to the autofocus API

def af_query(ident,query):

    # A callable to find the proper field_value for the input_type hash, based on the query_value
    def map_hash_value(qv):
        if len(qv) == 32:
            return "sample.md5"
        if len(qv) == 40:
            return "sample.sha1"
        if len(qv) == 64:
            return "sample.sha256"
        raise Exception("Unknown hash type")

    # Create a map of input_type to field_value
    field_map = {
        "ip"            : "alias.ip_address",
        "dns"           : "alias.domain",
        "hash"          : map_hash_value,
        "http"          : "sample.tasks.http",
        "file"          : "sample.tasks.file",
        "process"       : "sample.tasks.process",
        "mutex"         : "sample.tasks.mutex",
        "registry"      : "sample.tasks.registry",
        "service"       : "sample.tasks.service",
        "connection"    : "sample.tasks.connection",
        "user_agent"    : "sample.tasks.user_agent",
        "tag"           : "sample.tag",
        "hash_list"     : "sample.sha256",
        "file_url"      : "session.fileurl",
        "file_name"     : "alias.filename"
    }

    # Create a map of input_type to operator
    operator_map = {
        "hash"          : "is",
        "user_agent"    : "is",
        "tag"           : "is in the list",
        "hash_list"     : "is in the list"
    }

    # Lookup the operator to use with this input type
    operator_value = operator_map.get(ident, "contains")

    try:
        # Get the field value from the map
        field_value = field_map[ident]

        # Is the query value callable? Call it with the query_value to get the field value (hashes)
        if isfunction(field_value):
            field_value = field_value(query)
    except Exception as e:
        # Mimic the original catch all, if we don't know what the field is, just exit
        raise e

    # Everything that is a list (including hash_list and tag)
    if operator_value == "is in the list":
        params = [v.strip() for v in query.split(",")]

        # if we have less than 100 params, we only need one query field
        if len(params) <= 100:
            return '{"operator":"all","children":[{"field":"%s","operator":"%s","value":[%s]}]}' % (field_value, operator_value, ",".join(['"{}"'.format(v) for v in params]))

        else:
            # split our params into a list of lists so as to create queries with <=100 elements each.
            chunked_params = [params[index:index + 100] for index in xrange(0, len(params), 100)]

            # Build multiple groups of "in the list" queries
            groups = ",".join(['{"field":"%s","operator":"%s","value":[%s]}' % (field_value, operator_value, ",".join(['"{}"'.format(v) for v in chunk])) for chunk in chunked_params])

            # compile them into the final query.
            return '{"operator":"any","children":[%s]}' % groups
    else:

        return '{"operator":"all","children":[{"field":"%s","operator":"%s","value":"%s"}]}' % (field_value, operator_value, query)

###########################
# FUNCTION SECTIONS BELOW #
###########################

# Hash Library Function
# Builds the hash library which is used by every other function
# Returns data as dictionary with each key being the hash and a dictionary value with each section featuring a list {hash:{section:[value1,value2]}}

def hash_library(args):

    result_data = {}
    input_data  = []
    
    if not args.quiet:
        print "\n[+] hashes [+]\n"

    if research_mode == "True":
        poll_af = AFSample.scan
    else:
        poll_af = AFSample.search

    count = 0
    if args.ident == "query":
        for sample in poll_af(args.query):
            if count < args.limit:
                input_data.append(sample.sha256)
                count += 1
            else:
                break

    else:
        for sample in poll_af(af_query(args.ident,args.query)):
            if count < args.limit:
                input_data.append(sample.sha256)
                count += 1
            else:
                break

    # Set the number of workers to be three times the number of cores.
    # These operations are not very CPU-intensive, we can get away with a higher number of processes.
    pool_size = multiprocessing.cpu_count() * 3

    pool = multiprocessing.Pool(processes=pool_size)
    # Since we have to pass an iterable to pool.map(), and our worker function requires args to be passed we need to build a dictionary consisting of tuples. e.g:
    # [ (args, hash_1), (args, hash_2), (args, hash_n) ]
    pool_output = pool.map(hash_worker,[(args,item) for item in input_data])
    pool.close()
    pool.join()

    for item in pool_output:
        # structure of item is [{'hash' : { analysis data keys/values }}]
        result_data[item.keys()[0]] = item[item.keys()[0]]

    return result_data

# Hash worker function
# Designed be be used for parallel processing of samples
# Takes single tuple as argument from pool.map() and transforms those arguments to be used
# in hash_lookup()

def hash_worker(args_tuple):

    args,sample_hash = args_tuple

    if not args.quiet:
        print(sample_hash)

    return { sample_hash : hash_lookup(args,sample_hash) }


# Hash Lookup Function
# Basic hash lookup for a sample
# Provides raw data for each section requested

def hash_lookup(args, query):

    # Dictionary mapping the raw data for each type of sample analysis
    analysis_data = build_field_list()

    # Map analysis types to analysis_data keys
    analysis_data_map = {
        AFServiceActivity                   : "service",
        AFRegistryActivity                  : "registry",
        AFProcessActivity                   : "process",
        AFJavaApiActivity                   : "japi",
        AFApiActivity                       : "misc",
        AFUserAgentFragment                 : "user_agent",
        AFMutexActivity                     : "mutex",
        AFHttpActivity                      : "http",
        AFDnsActivity                       : "dns",
        AFBehaviorAnalysis                  : "behavior_desc",
        AFBehaviorTypeAnalysis              : "behavior_type",
        AFConnectionActivity                : "connection",
        AFFileActivity                      : "file",
        AFApkActivityAnalysis               : "apk_misc",
        AFApkIntentFilterAnalysis           : "apk_filter",
        AFApkReceiverAnalysis               : "apk_receiver",
        AFApkSensorAnalysis                 : "apk_sensor",
        AFApkServiceAnalysis                : "apk_service",
        AFApkEmbededUrlAnalysis             : "apk_embedurl",
        AFApkRequestedPermissionAnalysis    : "apk_permission",
        AFApkSensitiveApiCallAnalysis       : "apk_sensitiveapi",
        AFApkSuspiciousApiCallAnalysis      : "apk_suspiciousapi",
        AFApkSuspiciousFileAnalysis         : "apk_file",
        AFApkSuspiciousStringAnalysis       : "apl_string"
    }

    # If there are no counts for the activity, ignore them for the filter
    for sample in AFSample.search(af_query("hash",query)):
        for analysis in sample.get_analyses():

            analysis_data_section = analysis_data_map.get(type(analysis), "default")

            try:
                # Logic for "highly_suspicious" and "suspicious" indicators filter
                if args.targetted:
                    if (analysis.malware_count > (analysis.benign_count * 3)) and (analysis.malware_count < 500):
                        analysis_data[analysis_data_section].append(analysis._raw_line)
                elif args.untargetted:
                    if analysis.malware_count > (analysis.benign_count * 3) and (analysis.malware_count >= 500):
                        analysis_data[analysis_data_section].append(analysis._raw_line)
                elif (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < args.filter:
                    analysis_data[analysis_data_section].append(analysis._raw_line)
            except:
                pass

            # Handle Behaviors which have no BGM values
            if type(analysis) == AFBehaviorTypeAnalysis or type(analysis) == AFBehaviorAnalysis:
                analysis_data[analysis_data_section].append(analysis._raw_line)

        if sample.imphash:
            analysis_data["imphash"].append(sample.imphash)

        if sample.digital_signer:
            analysis_data["digital_signer"].append(sample.digital_signer)

    return analysis_data

# Common Artifacts Function
# Identifies lines that exist, per section, in every identified sample
# Must be a 100% match, unless adjusted by -c flag, across all samples to be reported, thus samples that unique every install may not have certain entries appear

def common_artifacts(args):

    commonality = float(args.commonality)/float(100)

    # Used for collecting all of the artifacts and counts
    compare_data = build_field_dict()

    # Final collection of all common artifacts
    common_data = build_field_list()

    count   = 0
    hashes  = hash_library(args)

    for hash in hashes.keys():

        # Sample data
        hash_data = build_field_dict()

        for section in hashes[hash]:
            for value in hashes[hash][section]:

                if value in compare_data[section] and value not in hash_data[section]:
                    compare_data[section][value] += 1
                    hash_data[section][value] = 1

                if value not in compare_data[section] and value not in hash_data[section]:
                    hash_data[section][value] = 1
                    compare_data[section][value] = 1
        count += 1

    for section in compare_data:
        for value in compare_data[section]:
            if float(compare_data[section][value])/float(count) >= commonality:

                match_percent = int(float(compare_data[section][value])/float(count) * 100)

                if "range" in args.special:
                    common_data[section].append("%-3s | " % (match_percent) + value)
                else:
                    common_data[section].append(value)

    common_data['count'] = count # Keep track of how many samples processed

    return common_data

# Common Pieces Function
# Similar to the "comnmon_artifact" function, but further breaks down each line to look for commonalities
# Will have more hits but likely less accurate

def common_pieces(args):

    commonality = float(args.commonality)/float(100)

    # Used for collecting all of the artifacts and counts
    compare_data = build_field_dict()

    # Final collection of all common pieces
    common_pieces = build_field_list()

    count   = 0
    hashes  = hash_library(args)

    for hash in hashes.keys():

        # Sample data
        hash_data = build_field_dict()
        for section in hashes[hash]:
            for value in hashes[hash][section]:

                section_data = value.split(" , ")

                for piece in section_data:

                    if piece in compare_data[section] and piece not in hash_data[section]:
                        compare_data[section][piece] += 1
                        hash_data[section][piece] = 1

                    if piece not in compare_data[section] and piece not in hash_data[section]:
                        hash_data[section][piece] = 1
                        compare_data[section][piece] = 1
        count += 1

    for section in compare_data:
        for value in compare_data[section]:
            if float(compare_data[section][value])/float(count) >= commonality:

                match_percent = int(float(compare_data[section][value])/float(count) * 100)

                if "range" in args.special:
                    common_pieces[section].append("%-3s | " % (match_percent) + value)
                else:
                    common_pieces[section].append(value)

    common_pieces['count'] = count # Keep track of how many samples processed

    # Clear out behavior descriptions so it doesn't print - doesn't really make sense for this context
    # Comment out to add them back in
    common_pieces['behavior_desc'] = []

    return common_pieces

# Unique Sessions Function
# Will gather session data from the identified samples and then report back the unique values per section
# Session data isn't normalized quite the same as sample data so this may be more error-prone

def uniq_sessions(args):

    session_data = build_session_list()

    count = 0

    if args.ident == "query":
        query = args.query
    else:
        query = af_query(args.ident,args.query)

    if research_mode == "True":
        poll_af = AFSession.scan
    else:
        poll_af = AFSession.search

    for session in poll_af(query):

        unique_list = []
        for section in session_data:
            if args.special == "count" and session.__dict__[section] and session.__dict__[section] not in unique_list:
                session_data[section].append(session.__dict__[section])
                unique_list.append(session.__dict__[section])
            else:
                if session.__dict__[section] not in session_data[section] and session.__dict__[section]:
                    session_data[section].append(session.__dict__[section])

        count += 1

        if count >= args.limit:
            break

    if args.special == "count":
        session_data = count_values(session_data)

    session_data['count'] = count

    return session_data

# Count Values Function
# Totals up the unique values per section
# Works with hash and session function

def count_values(count_list):

    for section in count_list:

        unique_values = []

        for value in count_list[section]:
            unique_values.append("%-4s | %s" % (count_list[section].count(value), value))

        count_list[section] = []

        for value in unique_values:
            if value not in count_list[section]:
                count_list[section].append(value)

    return count_list

# Hash Scraper Function
# Extracts all data from each section of the identified samples
# BGM filtering is done on the entire line

def hash_scrape(args):

    hash_data = build_field_list()

    count   = 0
    hashes  = hash_library(args)

    for hash in hashes:
        for section in hashes[hash]:
            unique_list = []
            for value in hashes[hash][section]:
                if args.special == "count" and value not in unique_list:
                    hash_data[section].append(value)
                    unique_list.append(value)
                else:
                    if value not in hash_data[section]:
                        hash_data[section].append(value)
        count += 1

    if args.special == "count":
        hash_data = count_values(hash_data)

    hash_data['count'] = count # Keep track of how many samples processed

    return hash_data

# HTTP Scraper Function
# Extracts all HTTP requests made from the identified samples
# BGM filtering is done on the entire line

def http_scrape(args):

    http_data   = {"http":[]}
    count       = 0
    hashes      = hash_library(args)

    for hash in hashes.keys():

        sample_data = hashes[hash]

        for entry in sample_data['http']:
            http_list = entry.split(" , ")
            url_value = "hxxp://" + http_list[0] + http_list[2]
            if url_value not in http_data['http']:
                http_data['http'].append(url_value)
        count += 1

    http_data['count'] = count # Keep track of how many samples processed

    return http_data

# DNS Scraper Function
# Extracts all DNS queries made from the identified samples
# BGM filtering is done on the entire line

def dns_scrape(args):

    dns_data    = {"dns":[]}
    count       = 0
    hashes      = hash_library(args)

    for hash in hashes.keys():

        sample_data = hashes[hash]

        for entry in sample_data['dns']:

            dns_list    = entry.split(" , ")
            dns_query   = dns_list[0]

            if dns_query not in dns_data['dns']:
                dns_data['dns'].append(dns_query)
        count += 1

    dns_data['count'] = count # Keep track of how many samples processed

    return dns_data

# Mutex Scraper Function
# Extracts all mutexes created within the identified samples
# BGM filtering is done on the entire line

def mutex_scrape(args):

    mutex_data  = {"mutex":[]}
    count       = 0
    hashes      = hash_library(args)

    for hash in hashes.keys():

        sample_data = hashes[hash]

        for entry in sample_data['mutex']:

            mutex_list  = entry.split(" , ")
            mutex_value = mutex_list[2]

            if mutex_value not in mutex_data['mutex']:
                mutex_data['mutex'].append(mutex_value)
        count += 1

    mutex_data['count'] = count # Keep track of how many samples processed

    return mutex_data

# Flat file reader function
# Reads lines in from a file while checking for sha256 hashes.
# Returns a list of hashes.

def fetch_hashes_from_file(args,input_file):

    hashlist = []

    if not args.quiet:
        print("[+] Attempting to read files from {}".format(input_file))

    try:
        with open(input_file,'r') as fh:

            for line in fh.readlines():

                line = line.strip()

                if re.match('^[0-9a-zA-Z]{64}$',line):
                    hashlist.append(line)
                else:
                    # Ignore any malformed hashes or bad lines
                    pass

    except IOError as e:
        print("[!] Error. {}: {}".format(e.strerror,e.filename))
        sys.exit(2)

    return hashlist

# Diff Function
# Extracts all data from each section of the identified samples and finds differences
# BGM filtering is done on the entire line

def diff(args):

    hash_data = build_field_list()

    # Only compare two hashes for diff
    args.limit  = 2

    hashes      = hash_library(args)
    hash_list   = []

    for hash in hashes:
        hash_list.append(hash)

    print "\n[+] diff [+]\n\n< | %s\n> | %s" % (hash_list[0], hash_list[1])

    count = 0

    for hash in hash_list:
        for section in hashes[hash]:

            if count == 1 and hash_data[section] != []:
                hash_data[section].append("---")

            for value in hashes[hash][section]:
                if count == 0:
                    if value not in hashes[hash_list[1]][section]:
                        hash_data[section].append("< | " + value)
                    #else:
                        #hash_data[section].append(value) # Prints matching line, uncomment to add in
                else:
                    if value not in hashes[hash_list[0]][section]:
                        hash_data[section].append("> | " + value)
        count += 1

    hash_data['count'] = count

    return hash_data


########################
# OUTPUT SECTION BELOW #
########################

# Output Analysis Function
# This is what gets printed out to the screen
# Takes a normalized input of sections and returns the sections requested by the user

def output_analysis(args, sample_data, funct_type):

    output = args.output.split(",")

    # SESSIONS: email_subject, file_name, application, dst_country, src_country industry, email_sender, email_recipient, account_name,
    #           file_url, dst_port, src_port, dst_ip, src_ip, timestamp
    # SAMPLES: service, registry, process, misc, user_agent, mutex, http, dns, behavior_desc, behavior_type, connection, file, apk_misc, apk_filter,
    #           apk_receiver, apk_sensor, apk_service, apk_embedurl,apk_permission, apk_sensitiveapi, apk_suspiciousapi, apk_file,
    #           apk_string. digital_signer, imphash

    section_list = [
        "email_subject",
        "file_name",
        "application",
        "dst_country",
        "src_country",
        "dst_ip",
        "src_ip",
        "dst_port",
        "src_port",
        "industry",
        "email_sender",
        "file_url",
        "email_recipient",
        "account_name",
        "timestamp",
        "service",
        "registry",
        "process",
        "misc",
        "user_agent",
        "mutex",
        "http",
        "dns",
        "behavior_desc",
        "behavior_type",
        "connection",
        "file",
        "apk_misc",
        "apk_filter",
        "apk_receiver",
        "apk_sensor",
        "apk_service",
        "apk_embedurl",
        "apk_permission",
        "apk_sensitiveapi",
        "apk_suspiciousapi",
        "apk_file",
        "apk_string",
        "digital_signer",
        "imphash",
        "default"
    ]

    if "all" in output:
        for entry in section_list:
            if entry in sample_data.keys() and sample_data[entry] != []:
                if not args.quiet:
                    print "\n[+]", entry, "[+]\n"
                for value in sample_data[entry]:
                    if value != "":
                        print value
    else:
        for entry in output:
            if entry in sample_data.keys() and sample_data[entry] != []:
                if not args.quiet:
                    print "\n[+]", entry, "[+]\n"
                for value in sample_data[entry]:
                    if value != "":
                        print value

    if not args.quiet:
        if funct_type == "sample":
            print "\n[+] processed", sample_data['count'], "hashes with a BGM filter of", str(args.filter), "[+]\n"
        elif funct_type == "session":
            print "\n[+] processed", sample_data['count'], "sessions [+]\n"

# Output List Function
# This just returns sample based meta-data based on the query provided
# Intended to be filtered/sorted afterwards by "|" pipe delimited characters

def build_output_string(output, item, type):

    #
    # Meta
    #
    if type == "meta":
        meta_sections = {"tags"             : ",".join(item._tags),
                         "sha256"           : item.sha256,
                         "file_type"        : item.file_type,
                         "create_date"      : str(item.create_date),
                         "verdict"          : item.verdict,
                         "file_size"        : str(item.size),
                         "digital_signer"   : item.digital_signer,
                         "sha1"             : item.sha1,
                         "md5"              : item.md5,
                         "ssdeep"           : item.ssdeep,
                         "imphash"          : item.imphash
                         }
        print_list = []

        if "all" in output: # Not literally 'all' in this particular case - more aligned to default UI display of AutoFocus

            all_sections = ["sha256",
                            "file_type",
                            "create_date",
                            "verdict",
                            "file_size",
                            "tags"]
            for entry in all_sections:
                if meta_sections[entry] == None:
                    print_list.append("None")
                else:
                    print_list.append(meta_sections[entry])
        else:
            for entry in output:
                if entry in meta_sections:
                    print_list.append("%s" % meta_sections[entry])

    #
    # Session
    #
    elif type == "session":
        meta_sections = {"email_subject"    : item.email_subject,
                         "file_name"        : item.file_name,
                         "application"      : item.application,
                         "dst_country"      : item.dst_country,
                         "src_country"      : item.src_country,
                         "dst_ip"           : item.dst_ip,
                         "src_ip"           : item.src_ip,
                         "dst_port"         : item.dst_port,
                         "src_port"         : item.src_port,
                         "industry"         : item.industry,
                         "email_sender"     : item.email_sender,
                         "file_url"         : item.file_url,
                         "email_recipient"  : item.email_recipient,
                         "account_name"     : item.account_name,
                         "timestamp"        : str(item.timestamp)
                         }
        print_list = []

        if "all" in output: # Not literally 'all' in this particular case - more aligned to default UI display of AutoFocus

            all_sections = ["timestamp",
                            "account_name",
                            "email_sender",
                            "email_subject",
                            "file_name",
                            "file_url"]
            for entry in all_sections:
                if meta_sections[entry] == None:
                    print_list.append("None")
                else:
                    print_list.append(meta_sections[entry])
        else:
            for entry in output:
                if entry in meta_sections:
                    print_list.append("%s" % meta_sections[entry])

    return print_list

def output_list(args):

    output  = args.output.split(",")
    count   = 0
    results = []

    #
    # Meta Scrape
    #
    if args.run == "meta_scrape":

        if research_mode == "True":
            poll_af = AFSample.scan
        else:
            poll_af = AFSample.search

        if not args.quiet:
            print "\n[+] sample_meta [+]\n"

        if args.ident == "query":
                for sample in poll_af(args.query):
                    print_line = build_output_string(output, sample, "meta")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        else:
                for sample in poll_af(af_query(args.ident,args.query)):
                    print_line = build_output_string(output, sample, "meta")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        # Auto-adjust column widths
        widths = [max(map(len,col)) for col in zip(*results)]
        for row in results:
            print " | ".join((val.ljust(width) for val, width in zip(row, widths)))

        if not args.quiet:
            print "\n[+] processed", str(count), "samples [+]\n"

    #
    # Session scrape
    #
    if args.run == "session_scrape":

        if research_mode == "True":
            poll_af = AFSession.scan
        else:
            poll_af = AFSession.search

        if not args.quiet:
            print "\n[+] session_meta [+]\n"

        if args.ident == "query":
                for session in poll_af(args.query):
                    print_line = build_output_string(output, session, "session")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        else:
                for session in poll_af(af_query(args.ident,args.query)):
                    print_line = build_output_string(output, session, "session")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        # Auto-adjust column widths
        widths = [max(map(len,col)) for col in zip(*results)]
        for row in results:
            print " | ".join((val.ljust(width) for val, width in zip(row, widths)))

        if not args.quiet:
            print "\n[+] processed", str(count), "sessions [+]\n"

# AutoFocus Import Function
# Builds a query for import into AutoFocus based on returned results
# AutoFocus API has a limit on the lines allowed and too many results will make it more challenging to manage in the portal

def af_import(args, sample_data):

    # Initialize some values
    output = args.output.split(",")

    if "all" in output:
        output = []
        for key in sample_data.keys():
            output.append(key)

    # Build AutoFocus query
    if not args.quiet:
        print "[+] af import query [+]\n"

    import_query = '{"operator":"all","children":['
    for entry in output:
        if entry in sample_data.keys() and entry == "dns":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.dns","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "http":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.http","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "connection":
            for value in sample_data[entry]:
                value_split = value.split(" , ")
                for subvalue in value_split: # Instead of trying to parse all of the different formats for connection, just include IP:DPORT
                    if ":" in subvalue:
                        import_query += '{"field":"sample.tasks.connection","operator":"contains","value":"' + subvalue + '"},'
        if entry in sample_data.keys() and entry == "user_agent":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.user_agent","operator":"is","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "mutex":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.mutex","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "process":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.process","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "file":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.file","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "registry":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.registry","operator":"contains","value":"' + value + '"},'
        if entry in sample_data.keys() and entry == "service":
            for value in sample_data[entry]:
                import_query += '{"field":"sample.tasks.service","operator":"contains","value":"' + value + '"},'
    import_query += ']}'
    import_query = import_query[:len(import_query) - 3] + import_query[-2:]
    import_query = str(import_query.replace("\\", "\\\\")) # Double escape for AF

    print import_query + "\n"

# Yara Rule Function
# Attempts to take the likely data you might find from dynamic analysis and build a yara rule for memory process scanning using volatility/other tools
# Some sections commented out as they generate far too many entries/false positives that haven't been programatically filtered

def yara_rule(args, sample_data):

    # Initialize some values
    output = args.output.split(",")

    if "all" in output:
        output = []
        for key in sample_data.keys():
            output.append(key)

    if not args.quiet:
        print "[+] yara rule [+]\n"

    min_len         = 4 # Minimum string length
    contained_list  = []
    entry_list      = []

    # Build yara rule
    yara_sig = "rule autogen_afLenz\n{\n\t// %s\n\n\tstrings:\n" % args

    for entry in output:
        if entry in sample_data.keys() and entry == "dns":
            count = 0

            if args.run == "dns_scrape":
                for value in sample_data[entry]:
                    if value not in contained_list and value != "" and len(value) > min_len:
                        entry_list.append("dns")
                        contained_list.append(value)
                        yara_sig += "\t\t$dns_" + str(count) + " = \"" + value + "\" wide ascii\n" # Just grab the domain
                        count += 1
            else:
                for value in sample_data[entry]:
                    dns_entry = value.split(" , ")[0]
                    dns_resolve = value.split(" , ")[1]
                    if dns_entry not in contained_list and dns_entry != "" and len(dns_entry) > min_len:
                        entry_list.append("dns")
                        contained_list.append(dns_entry)
                        yara_sig += "\t\t$dns_" + str(count) + " = \"" + dns_entry + "\" wide ascii\n" # Just grab the domain
                    if dns_resolve not in contained_list and dns_resolve != "" and len(dns_resolve) > min_len:
                        entry_list.append("dns")
                        contained_list.append(dns_resolve)
                        yara_sig += "\t\t$dns_" + str(count+1) + " = \"" + dns_resolve + "\" wide ascii\n" # Just grab the resolved IP
                    count += 2

        if entry in sample_data.keys() and entry == "http":
            count = 0
            if args.run == "http_scrape":
                for value in sample_data[entry]:
                    value = value.replace("hxxp", "http")
                    if value not in contained_list and value != "" and len(value) > min_len:
                        entry_list.append("http")
                        contained_list.append(value)
                        yara_sig += "\t\t$http_" + str(count) + " = \"" + value + "\" wide ascii\n" # Just grab the domain
                        count += 1
            else:
                for value in sample_data[entry]:
                    domain_name = value.split(" , ")[0]
                    try:
                        url_path = value.split(" , ")[2]
                    except:
                        url_path = ""
                    try:
                        full_ua = value.split(" , ")[3]
                    except:
                        full_ua = ""
                    if domain_name not in contained_list and domain_name != "" and len(domain_name) > min_len:
                        entry_list.append("http")
                        contained_list.append(domain_name)
                        yara_sig += "\t\t$http_" + str(count) + " = \"" + domain_name + "\" wide ascii\n" # Just grab the domain
                    if url_path not in contained_list and url_path != "" and len(url_path) > min_len:
                        entry_list.append("http")
                        contained_list.append(url_path)
                        yara_sig += "\t\t$http_" + str(count+1) + " = \"" + url_path + "\" wide ascii\n" # Just grab the URL path
                    if full_ua not in contained_list and full_ua != "" and len(full_ua) > min_len:
                        entry_list.append("http")
                        contained_list.append(full_ua)
                        yara_sig += "\t\t$http_" + str(count+2) + " = \"" + full_ua + "\" wide ascii\n" # Just grab the full user-agent
                    count += 3

        if entry in sample_data.keys() and entry == "connection":
            count = 0
            for value in sample_data[entry]:
                value_split = value.split(" , ")
                for subvalue in value_split:
                    if ":" in subvalue and subvalue not in contained_list and len(subvalue) > min_len:
                        entry_list.append("connection")
                        contained_list.append(subvalue.split(":")[0])
                        yara_sig += "\t\t$connection_" + str(count) + " = \"" + subvalue.split(":")[0] + "\"\n" # Just grab IP
                count += 1

        if entry in sample_data.keys() and entry == "user_agent":
            count = 0
            for value in sample_data[entry]:
                if value not in contained_list and value != "" and len(value) > min_len:
                    entry_list.append("user_agent")
                    contained_list.append(value)
                    yara_sig += "\t\t$user_agent_" + str(count) + " = \"" + value + "\"\n" # Just grab the UA fragment
                count += 1

        if entry in sample_data.keys() and entry == "mutex":
            mutex_blacklist = ["Local\!IETld!Mutex",
                               "IESQMMUTEX_0_208",
                               "c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!",
                               "c:!documents and settings!administrator!cookies!",
                               "c:!documents and settings!administrator!local settings!history!history.ie5!",
                               "WininetConnectionMutex",
                               "<NULL>"] # Entries to ignore
            count = 0
            if args.run == "mutex_scrape":
                for mutex in sample_data[entry]:
                    if mutex not in contained_list and mutex != "" and mutex not in mutex_blacklist and len(mutex) > min_len:
                        entry_list.append("mutex")
                        contained_list.append(mutex)
                        yara_sig += "\t\t$mutex_" + str(count) + " = \"" + mutex + "\"\n" # Just grab the domain
                        count += 1
            else:
                for mutex in sample_data[entry]:
                    mutex = mutex.split(" , ")[2]
                    if mutex not in contained_list and mutex != "" and mutex not in mutex_blacklist and len(mutex) > min_len: # Just grab mutex name
                        entry_list.append("mutex")
                        contained_list.append(mutex)
                        yara_sig += "\t\t$mutex_" + str(count) + " = \"" + mutex + "\"\n"
                    count += 1
                    #
                    # The below are commented out simply because they generate a LOT of data and noise. Uncomment if necessary.
                    #
                    #if entry in sample_data.keys() and entry == "process":
                    #    count = 0
                    #    for value in sample_data[entry]:
                    #        entry_list.append("process")
                    #        yara_sig += "\t\t$process_" + str(count) + " = \"" + value + "\"\n" # A bit too noisy and FP prone
                    #        count += 1
                    #if entry in sample_data.keys() and entry == "file":
                    #    count = 0
                    #    for value in sample_data[entry]:
                    #        file_name = value.split(" , ")[2].strip("C:\\")
                    #        if file_name not in contained_list and file_name != "" and len(file_name) > min_len:
                    #            entry_list.append("file")
                    #            contained_list.append(file_name)
                    #            yara_sig += "\t\t$file_" + str(count) + " = \"" + file_name + "\"\n" # Just grab file path/name
                    #        count += 1
                    #if entry in sample_data.keys() and entry == "registry":
                    #    count = 0
                    #    for value in sample_data[entry]:
                    #        registry_key = value.split(" , ")[2].split(",")[0]
                    #        if registry_key not in contained_list and registry_key != "" and "\\" in registry_key and len(registry_key) > min_len:
                    #            entry_list.append("registry")
                    #            contained_list.append(registry_key)
                    #            yara_sig += "\t\t$registry_" + str(count) + " = \"" + registry_key + "\"\n"
                    #        count += 1

    entry_list = list(set(entry_list))

    yara_sig += "\n\tcondition:\n\t\t1 of (" + ", ".join(["$" + value + "*" for value in entry_list]) + ") /* Adjust as needed for accuracy */\n}"
    yara_sig = str(yara_sig.replace("\\", "\\\\")) # Double escape for yara

    if "$" in yara_sig:
        print yara_sig + "\n"
    elif not args.quiet:
        print "No yara rule could be generated.\n"

################
# MAIN PROGRAM #
################

def main():

    # Set initial values
    functions = [
        "uniq_sessions",
        "common_artifacts",
        "common_pieces",
        "hash_scrape",
        "http_scrape",
        "dns_scrape",
        "mutex_scrape",
        "meta_scrape",
        "session_scrape",
        "diff"
    ]
    session_sections = [
        "email_subject",
        "file_name",
        "application",
        "dst_country",
        "src_country",
        "dst_ip",
        "src_ip",
        "dst_port",
        "src_port",
        "industry",
        "email_sender",
        "file_url",
        "email_recipient",
        "account_name",
        "timestamp"
    ]
    sample_sections = [
        "service",
        "registry",
        "process",
        "misc",
        "japi",
        "user_agent",
        "mutex",
        "http",
        "dns",
        "behavior_desc",
        "behavior_type",
        "connection",
        "file",
        "apk_misc",
        "apk_filter",
        "apk_receiver",
        "apk_sensor",
        "apk_service",
        "apk_embedurl",
        "apk_permission",
        "apk_sensitiveapi",
        "apk_suspiciousapi",
        "apk_file",
        "apk_string",
        "digital_signer",
        "imphash"
    ]
    meta_sections = [
        "sha256",
        "file_type",
        "create_date",
        "verdict",
        "file_size",
        "tags",
        "sha1",
        "md5",
        "ssdeep",
        "imphash",
        "digital_signer"
    ]
    identifiers = [
        "hash",
        "hash_list",
        "ip",
        "connection",
        "dns",
        "file",
        "http",
        "mutex",
        "process",
        "registry",
        "service",
        "user_agent",
        "tag",
        "query",
        "input_file"
    ]
    specials = [
        "yara_rule",
        "af_import",
        "range",
        "count"
    ]

    # Grab initial arguments from CLI
    parser = argparse.ArgumentParser(description="Run functions to retrieve information from AutoFocus.")
    parser.add_argument("-i", "--ident", help="Query identifier type for AutoFocus search. [" + ", ".join(identifiers) + "]", metavar='<query_type>', required=True)
    parser.add_argument("-q", "--query", help="Value to query Autofocus for.", metavar='<query>', required=True)
    parser.add_argument("-o", "--output", help="Section of data to return. Multiple values are comma separated (no space) or \"all\" for everything, which is default. "
                                               "Sample Sections [" + ", ".join(sample_sections) + "]. "
                                                                                                  "Session Sections [" + ", ".join(session_sections) + "]. "
                                                                                                                                                       "Meta Sections [" + ", ".join(meta_sections) + "]", metavar='<section_output>', default="all")
    parser.add_argument("-f", "--filter", help="Filter out Benign/Grayware/Malware counts over this number, default 10,000.", metavar="<number>", type=int, default=10000)
    parser.add_argument("-l", "--limit", help="Limit the number of analyzed samples, default 200.", metavar="<number>", type=int, default=200)
    parser.add_argument("-r", "--run", choices=functions, help="Function to run. [" + ", ".join(functions) + "]", metavar='<function_name>', required=True)
    parser.add_argument("-s", "--special", choices=specials, help="Output data formated in a special way for other tools. [" + ", ".join(specials) + "]", metavar="<special_output>",default=[])
    parser.add_argument("-c", "--commonality", help="Commonality percentage for comparison functions, default is 100", metavar="<integer_percent>", type=int, default=100)
    parser.add_argument("-Q", "--quiet",help="Suppress any informational output and only return data.",action="store_true",default=False)
    parser.add_argument("--highly_suspicious", help="Show only highly suspicious indicators", action="store_true", dest="targetted", default=False)
    parser.add_argument("--suspicious", help="Show only suspicious indicators", action="store_true", dest="untargetted", default=False)    
    args = parser.parse_args()
    args.query = args.query.replace("\\", "\\\\")

    if args.ident == "input_file":
        hashlist = fetch_hashes_from_file(args,args.query)
        # Build an AF query using the hash list that was just generated join the list into a comma-separated string, because this is what some other functions expect.
        args.query = af_query("hash_list",",".join(item for item in hashlist))
        args.ident = "query"

    # Gather results from functions
    funct_type = "sample"
    if not args.quiet:
        if args.ident == "query":
            print "\n", args.query
        else:
            print "\n" + af_query(args.ident,args.query).strip()

    if args.run == "uniq_sessions":
        out_data = uniq_sessions(args)
        funct_type = "session"
    elif args.run == "hash_scrape":
        out_data = hash_scrape(args)
    elif args.run == "common_artifacts":
        out_data = common_artifacts(args)
    elif args.run == "common_pieces":
        out_data = common_pieces(args)
    elif args.run == "http_scrape":
        out_data = http_scrape(args)
    elif args.run == "dns_scrape":
        out_data = dns_scrape(args)
    elif args.run == "mutex_scrape":
        out_data = mutex_scrape(args)
    elif args.run == "meta_scrape" or args.run == "session_scrape":
        out_data = {}
        funct_type = "list"
    elif args.run == "diff":
        out_data = diff(args)

    if "count" not in out_data:
        out_data['count'] = 1

    # If we have specified a -s option, do the following
    if "af_import" in args.special or "yara_rule" in args.special:
        if not args.quiet:
            if args.run == "meta_scrape" or args.run == "session_scrape":
                output_list(args)
            else:
                output_analysis(args, out_data, funct_type)

        if "af_import" in args.special:
            af_import(args, out_data)
        if "yara_rule" in args.special:
            yara_rule(args, out_data)

    else:
        if args.run == "meta_scrape" or args.run == "session_scrape":
            output_list(args)
        else:
            output_analysis(args, out_data, funct_type)

if __name__ == '__main__':
    main()
