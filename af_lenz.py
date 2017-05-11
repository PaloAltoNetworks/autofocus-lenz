#!/usr/bin/env python
from inspect import isfunction
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = ""
from autofocus import AFSession, AFSample, AFTag, AFTagDefinition
# Analysis Sections
from autofocus import \
    AFApiActivity, \
    AFBehaviorAnalysis, \
    AFBehaviorTypeAnalysis, \
    AFConnectionActivity, \
    AFDnsActivity, \
    AFFileActivity, \
    AFHttpActivity, \
    AFJavaApiActivity, \
    AFMutexActivity, \
    AFProcessActivity, \
    AFRegistryActivity, \
    AFServiceActivity, \
    AFUserAgentFragment
# APK Specific
from autofocus import \
    AFAnalysisSummary, \
    AFApkActivityAnalysis, \
    AFApkAppName, \
    AFApkCertificate, \
    AFApkEmbeddedFile, \
    AFApkEmbeddedLibrary, \
    AFApkEmbededUrlAnalysis, \
    AFApkIcon, \
    AFApkIntentFilterAnalysis, \
    AFApkPackage, \
    AFApkReceiverAnalysis, \
    AFApkRepackaged, \
    AFApkRequestedPermissionAnalysis, \
    AFApkSensitiveApiCallAnalysis, \
    AFApkSensorAnalysis, \
    AFApkServiceAnalysis, \
    AFApkSuspiciousActivitySummary, \
    AFApkSuspiciousApiCallAnalysis, \
    AFApkSuspiciousFileAnalysis, \
    AFApkSuspiciousPattern, \
    AFApkSuspiciousStringAnalysis, \
    AFApkVersion, \
    AFDigitalSigner
# MAC Specific
from autofocus import \
    AFMacEmbeddedFile, \
    AFMacEmbeddedURL

import sys, argparse, multiprocessing, os, re, json

__author__  = "Jeff White [karttoon]"
__email__   = "jwhite@paloaltonetworks.com"
__version__ = "1.2.1"
__date__    = "05APR2017"

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
        "apk_app_icon"                      : [],
        "apk_cert_file"                     : [],
        "apk_defined_activity"              : [],
        "apk_defined_intent_filter"         : [],
        "apk_defined_receiver"              : [],
        "apk_defined_sensor"                : [],
        "apk_defined_service"               : [],
        "apk_digital_signer"                : [],
        "apk_embedded_library"              : [],
        "apk_embeded_url"                   : [],
        "apk_internal_file"                 : [],
        "apk_isrepackaged"                  : [],
        "apk_name"                          : [],
        "apk_packagename"                   : [],
        "apk_requested_permission"          : [],
        "apk_sensitive_api_call"            : [],
        "apk_suspicious_action_monitored"   : [],
        "apk_suspicious_api_call"           : [],
        "apk_suspicious_file"               : [],
        "apk_suspicious_pattern"            : [],
        "apk_suspicious_string"             : [],
        "apk_version_num"                   : [],
        "behavior"                          : [],
        "behavior_type"                     : [],
        "connection"                        : [],
        "default"                           : [],
        "digital_signer"                    : [],
        "dns"                               : [],
        "file"                              : [],
        "http"                              : [],
        "imphash"                           : [],
        "japi"                              : [],
        "mac_embedded_file"                 : [],
        "mac_embedded_url"                  : [],
        "misc"                              : [],
        "mutex"                             : [],
        "process"                           : [],
        "registry"                          : [],
        "service"                           : [],
        "summary"                           : [],
        "user_agent"                        : []
    }

    return field_list

def build_field_dict():

    field_dict = {
        "apk_app_icon"                      : {},
        "apk_cert_file"                     : {},
        "apk_defined_activity"              : {},
        "apk_defined_intent_filter"         : {},
        "apk_defined_receiver"              : {},
        "apk_defined_sensor"                : {},
        "apk_defined_service"               : {},
        "apk_digital_signer"                : {},
        "apk_embedded_library"              : {},
        "apk_embeded_url"                   : {},
        "apk_internal_file"                 : {},
        "apk_isrepackaged"                  : {},
        "apk_name"                          : {},
        "apk_packagename"                   : {},
        "apk_requested_permission"          : {},
        "apk_sensitive_api_call"            : {},
        "apk_suspicious_action_monitored"   : {},
        "apk_suspicious_api_call"           : {},
        "apk_suspicious_file"               : {},
        "apk_suspicious_pattern"            : {},
        "apk_suspicious_string"             : {},
        "apk_version_num"                   : {},
        "behavior"                          : {},
        "behavior_type"                     : {},
        "connection"                        : {},
        "default"                           : {},
        "digital_signer"                    : {},
        "dns"                               : {},
        "file"                              : {},
        "http"                              : {},
        "imphash"                           : {},
        "japi"                              : {},
        "mac_embedded_file"                 : {},
        "mac_embedded_url"                  : {},
        "misc"                              : {},
        "mutex"                             : {},
        "process"                           : {},
        "registry"                          : {},
        "service"                           : {},
        "summary"                           : {},
        "user_agent"                        : {}
    }

    return field_dict

def build_session_list():

    session_list = {
        "application"           : [],
        "account_name"          : [],
        "device_country_code"   : [],
        "device_country"        : [],
        "device_hostname"       : [],
        "industry"              : [],
        "business_line"         : [],
        "device_model"          : [],
        "device_serial"         : [],
        "device_version"        : [],
        "dst_country_code"      : [],
        "dst_country"           : [],
        "dst_ip"                : [],
        "dst_port"              : [],
        "email_recipient"       : [],
        "email_charset"         : [],
        "email_sender"          : [],
        "email_subject"         : [],
        "file_name"             : [],
        "file_url"              : [],
        "src_country_code"      : [],
        "src_country"           : [],
        "src_ip"                : [],
        "src_port"              : [],
        "timestamp"             : []
    }

    return session_list

###############################
# MESSAGE PROCESSING FUNCTION #
###############################

def message_proc(message, args):

    if args.write:
        file_handle = open(args.write, "a")
        file_handle.write(("%s\n" % message).encode('utf-8'))
    else:
        print message.encode('utf-8')

    return


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
        "fileurl"      : "session.fileurl",
        "filename"     : "alias.filename"
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

        # if we have less than 999 params, we only need one query field
        if len(params) <= 999:
            return '{"operator":"all","children":[{"field":"%s","operator":"%s","value":[%s]}]}' % (field_value, operator_value, ",".join(['"{}"'.format(v) for v in params]))

        else:
            # split our params into a list of lists so as to create queries with <=999 elements each.
            chunked_params = [params[index:index + 999] for index in xrange(0, len(params), 999)]

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
        message_proc("\n[+] hashes [+]\n", args)

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
        message_proc(sample_hash, args)

    return { sample_hash : hash_lookup(args,sample_hash) }


# Hash Lookup Function
# Basic hash lookup for a sample
# Provides raw data for each section requested

def hash_lookup(args, query):

    # Dictionary mapping the raw data for each type of sample analysis
    analysis_data = build_field_list()

    # Map analysis types to analysis_data keys
    analysis_data_map = {
        #AFApkCertificate                    : "apk_certificate_id", # Client library passes both fields into one
        AFAnalysisSummary                   : "summary",
        AFApiActivity                       : "misc",
        AFApkActivityAnalysis               : "apk_defined_activity",
        AFApkAppName                        : "apk_name",
        AFApkCertificate                    : "apk_cert_file",
        AFApkEmbeddedFile                   : "apk_internal_file",
        AFApkEmbeddedLibrary                : "apk_embedded_library",
        AFApkEmbededUrlAnalysis             : "apk_embeded_url",
        AFApkIcon                           : "apk_app_icon",
        AFApkIntentFilterAnalysis           : "apk_defined_intent_filter",
        AFApkPackage                        : "apk_packagename",
        AFApkReceiverAnalysis               : "apk_defined_receiver",
        AFApkRepackaged                     : "apk_isrepackaged",
        AFApkRequestedPermissionAnalysis    : "apk_requested_permission",
        AFApkSensitiveApiCallAnalysis       : "apk_sensitive_api_call",
        AFApkSensorAnalysis                 : "apk_defined_sensor",
        AFApkServiceAnalysis                : "apk_defined_service",
        AFApkSuspiciousActivitySummary      : "apk_suspicious_action_monitored",
        AFApkSuspiciousApiCallAnalysis      : "apk_suspicious_api_call",
        AFApkSuspiciousFileAnalysis         : "apk_suspicious_file",
        AFApkSuspiciousPattern              : "apk_suspicious_pattern",
        AFApkSuspiciousStringAnalysis       : "apk_suspicious_string",
        AFApkVersion                        : "apk_version_num",
        AFBehaviorAnalysis                  : "behavior",
        AFBehaviorTypeAnalysis              : "behavior_type",
        AFConnectionActivity                : "connection",
        AFDigitalSigner                     : "apk_digital_signer",
        AFDnsActivity                       : "dns",
        AFFileActivity                      : "file",
        AFHttpActivity                      : "http",
        AFJavaApiActivity                   : "japi",
        AFMacEmbeddedFile                   : "mac_embedded_file",
        AFMacEmbeddedURL                    : "mac_embedded_url",
        AFMutexActivity                     : "mutex",
        AFProcessActivity                   : "process",
        AFRegistryActivity                  : "registry",
        AFServiceActivity                   : "service",
        AFUserAgentFragment                 : "user_agent"
    }

    # This may speed up large queries by reducing the volume of data returned from the API
    if args.output == "all":
        section_value = None
    else:
        section_value = []
        for section in args.output.split(","):
            for section_map in analysis_data_map:
                if section == analysis_data_map[section_map]:
                    section_value.append(section_map)

    # If there are no counts for the activity, ignore them for the filter
    for sample in AFSample.search(af_query("hash",query)):

        for analysis in sample.get_analyses(sections=section_value):

            analysis_data_section = analysis_data_map.get(type(analysis), "default")

            try:

                if args.special == "bgm":
                    raw_line = get_bgm(analysis)
                else:
                    raw_line = analysis._raw_line

                # Filter based on established values for low and high-distribution of malware artifacts, otherwise filter on aggregate counts for uniquness
                if args.filter == "suspicious":
                    if (analysis.malware_count > (analysis.benign_count * 3)) and (analysis.malware_count >= 500):
                        analysis_data[analysis_data_section].append(raw_line)
                elif args.filter == "highly_suspicious":
                    if analysis.malware_count > (analysis.benign_count * 3) and (analysis.malware_count < 500):
                        analysis_data[analysis_data_section].append(raw_line)
                elif (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < args.filter:
                    analysis_data[analysis_data_section].append(raw_line)
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

# BGM Function
# Returns human readable B(enign), G(rayware), and M(alware) counts
# Reduces large numbers to abbreivated versions

def get_bgm(analysis):

    count_list = [str(analysis.benign_count), str(analysis.grayware_count), str(analysis.malware_count)]
    raw_line = ""

    for number in count_list:

        if len(number) == 5: # 12345 = 12.3K
            number = "%s.%sK" % (number[:2], number[2])
        if len(number) == 6: # 123456 = 123K
            number = "%sK" % (number[:3])
        if len(number) == 7: # 1234567 = 1.2M
            number = "%s.%sM" % (number[:1], number[1])
        if len(number) == 8: # 12345678 = 12.3M
            number = "%s.%sK" % (number[:2], number[2])
        if len(number) == 9: # 123456789 = 123M
            number = "%sM" % (number[:3])
        if len(number) >= 10: # 1234567890 = 1B
            number = "%sB" % (number[:3])

        raw_line += "%-5s " % number

    raw_line += "| %s" % analysis._raw_line

    return raw_line

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

    common_data['count']    = count # Keep track of how many samples processed
    common_data['hashes'] = hashes.keys()

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

    common_pieces['count']  = count # Keep track of how many samples processed
    common_pieces['hashes'] = hashes.keys()

    # Clear out behavior descriptions so it doesn't print - doesn't really make sense for this context
    # Comment out to add them back in
    common_pieces['behavior'] = []

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
        session_data = count_values(session_data, args)

    session_data['count'] = count

    return session_data

# Count Values Function
# Totals up the unique values per section
# Works with hash and session function

def count_values(count_list, args):

    for section in count_list:

        if args.output == "all" or section in args.output:

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
        hash_data = count_values(hash_data, args)

    hash_data['count']  = count # Keep track of how many samples processed
    hash_data['hashes'] = hashes.keys()

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

    http_data['count']  = count # Keep track of how many samples processed
    http_data['hashes'] = hashes.keys()

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

    dns_data['count']   = count # Keep track of how many samples processed
    dns_data['hashes']  = hashes.keys()

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

    mutex_data['count']     = count # Keep track of how many samples processed
    mutex_data['hashes']    = hashes.keys()

    return mutex_data

# Service Scraper Function
# Extracts all service names from the identified samples
# BGM filtering is done on the entire line

def service_scrape(args):

    service_data    = {"service":[]}
    count       = 0
    hashes      = hash_library(args)

    for hash in hashes.keys():

        sample_data = hashes[hash]

        for entry in sample_data['service']:

            service_list    = entry.split(" , ")
            service_query   = service_list[2]

            if service_query not in service_data['service']:
                service_data['service'].append(service_query)
        count += 1

    service_data['count']   = count # Keep track of how many samples processed
    service_data['hashes']  = hashes.keys()

    return service_data

# Flat file reader function
# Reads lines in from a file while checking for sha256 hashes.
# Returns a list of hashes.

def fetch_from_file(args,input_file):

    if args.ident == "input_file":
        hashlist = []

        if not args.quiet:
            message_proc("\n[+] Attempting to read hashes from %s" % input_file, args)

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
            message_proc("\n[!] Error: %s - %s" % (e.strerror, e.filename), args)
            sys.exit(2)

        return hashlist

    elif args.ident == "input_file_query":

        if not args.quiet:
            message_proc("\n[+] Attempting to read query from %s" % input_file, args)

        try:
            with open(input_file, 'r') as fh:

                query = (fh.read()).strip()

        except IOError as e:
            message_proc("\n[!] Error: %s - %s" % (e.strerror, e.filename), args)
            sys.exit(2)

        return query

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

    message_proc("\n[+] diff [+]\n\n< | %s\n> | %s" % (hash_list[0], hash_list[1]), args)

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

    hash_data['count']  = count
    hash_data['hashes'] = hashes.keys()

    return hash_data

def tag_info(args):

    # Get tag info
    tag_info = AFTag.get(args.query)

    tag_details = ""

    tag_details += "\n%-15s : %s\n" % ("Tag Name", tag_info.name)
    tag_details += "%-15s : %s\n" % ("Tag Public Name", tag_info.public_name)
    tag_details += "%-15s : %s\n" % ("Tag Count", tag_info.count)
    tag_details += "%-15s : %s\n" % ("Tag Created", tag_info.created)
    tag_details += "%-15s : %s\n" % ("Tag Last Hit", tag_info.last_hit)
    tag_details += "%-15s : %s\n" % ("Tag Class", tag_info.tag_class)
    tag_details += "%-15s : %s\n" % ("Tag Status", tag_info.status)
    tag_details += "%-15s : %s\n" % ("Tag Description", tag_info.description)

    message_proc("\n[+] Tag Info [+]\n%s" % tag_details, args)

    sys.exit(1)

def tag_check(args):

    # Remove filter so all artifacts are checked
    args.filter = 1000000000

    tag_data = {"tag_value"  : args.query.split(",")[0],
                "hash_value" : args.query.split(",")[1]
                }

    # Get tag definitions
    tag_info = AFTag.get(tag_data["tag_value"])
    tag_def  = tag_info.tag_definitions

    # Get hash info
    args.query = tag_data["hash_value"]
    args.ident = "hash"

    hash_detail = hash_lookup(args, tag_data["hash_value"])

    hash_data = build_field_list()

    sections = build_field_list()
    matches = {}

    for section in hash_detail:
        for value in hash_detail[section]:
            if value not in hash_data[section]:
                hash_data[section].append(value)

    # Perform the tag check across sections
    def match_check(entry, match_flag):

        for section in sections:

            if section in entry["field"]:

                if section != "behavior_type" and section != "behavior":

                    # Contains / Is (search within)
                    if entry["operator"] == "contains" or entry["operator"] == "is":

                        for line in hash_detail[section]:

                            if entry["value"].lower() in line.lower(): # AF is case-insensitive here

                                match_flag = 1

                                entry_check = str(entry)
                                if entry_check not in matches:
                                    matches[entry_check] = {}
                                if section not in matches[entry_check]:
                                    matches[entry_check][section] = []
                                if line not in matches[entry_check][section]:
                                    matches[entry_check][section].append(line)

                    # Is in the list (split and re-iterate each)
                    if entry["operator"] == "is in the list":

                        for value in entry["value"]:

                            for line in hash_detail[section]:

                                if value.lower() in line.lower():

                                    match_flag = 1

                                    entry_check = str(entry)
                                    if entry_check not in matches:
                                        matches[entry_check] = {}
                                    if section not in matches[entry_check]:
                                        matches[entry_check][section] = []
                                    if line not in matches[entry_check][section]:
                                        matches[entry_check][section].append(line)

                    # AF Regex (modify AF regex to compliant statement)
                    # Attempt to convert proximity to regex - may be hit or miss
                    if entry["operator"] == "regexp" or entry["operator"] == "proximity":

                        af_regex = ".+".join(entry["value"].split(" "))

                        for line in hash_detail[section]:

                            if re.search(af_regex, line, re.IGNORECASE):

                                match_flag = 1

                                entry_check = str(entry)
                                if entry_check not in matches:
                                    matches[entry_check] = {}
                                if section not in matches[entry_check]:
                                    matches[entry_check][section] = []
                                if line not in matches[entry_check][section]:
                                    matches[entry_check][section].append(line)

        return match_flag

    for query in tag_def:

        match_flag = 0

        query = json.loads(str(query))

        # Attempt to wrap each query with a parent query using supplied hash
        # Should narrow down queries that need to be deconstructed for checking
        query_check = str(query)
        query_check = '{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"%s"},' % tag_data["hash_value"] + query_check
        query_check = query_check + ']}'
        query_check = query_check.replace("u'", "'")
        query_check = query_check.replace("'", "\"")
        query_check = query_check.replace("\\", "\\\\")

        for sample in AFSample.search(query_check):

            if sample.sha256 == tag_data["hash_value"]:

                for entry in query["children"]:

                    if "field" not in entry:

                        for child_entry in entry["children"]:

                            match_flag = match_check(child_entry, match_flag)

                    else:
                        match_flag = match_check(entry, match_flag)

                if match_flag == 0:

                    message_proc("\n[+] Unsupported Matched Query [+]\n\n%s" % query, args)

    for entry in matches:

        message_proc("\n[+] Matched Query [+]\n\n%s" % entry, args)

        for section in matches[entry]:

            message_proc("\n[+] %s [+]\n" % section, args)

            for line in matches[entry][section]:

                message_proc(line, args)

    tag_data['count'] = 1

    args.filter = 0

    return tag_data


########################
# OUTPUT SECTION BELOW #
########################

# Output Analysis Function
# This is what gets printed out to the screen
# Takes a normalized input of sections and returns the sections requested by the user

def output_analysis(args, sample_data, funct_type):

    output = args.output.split(",")

    section_list = [
        #Session
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
        #Sample
        "apk_app_icon",
        "apk_cert_file",
        "apk_defined_activity",
        "apk_defined_intent_filter",
        "apk_defined_receiver",
        "apk_defined_sensor",
        "apk_defined_service",
        "apk_digital_signer",
        "apk_embedded_library",
        "apk_embeded_url",
        "apk_internal_file",
        "apk_isrepackaged",
        "apk_name",
        "apk_packagename",
        "apk_requested_permission",
        "apk_sensitive_api_call",
        "apk_suspicious_action_monitored",
        "apk_suspicious_api_call",
        "apk_suspicious_file",
        "apk_suspicious_pattern",
        "apk_suspicious_string",
        "apk_version_num",
        "behavior",
        "behavior_type",
        "connection",
        "default",
        "digital_signer",
        "dns",
        "file",
        "http",
        "imphash",
        "japi",
        "mac_embedded_file",
        "mac_embedded_url",
        "misc",
        "mutex",
        "process",
        "registry",
        "service",
        "summary",
        "user_agent",
    ]

    if "all" in output:
        for entry in section_list:
            if entry in sample_data.keys() and sample_data[entry] != []:
                if not args.quiet:
                    message_proc("\n[+] %s [+]\n" % entry, args)
                for value in sample_data[entry]:
                    if value != "":
                        message_proc(value, args)
    else:
        for entry in output:
            if entry in sample_data.keys() and sample_data[entry] != []:
                if not args.quiet:
                    message_proc("\n[+] %s [+]\n" % entry, args)
                for value in sample_data[entry]:
                    if value != "":
                        message_proc(value, args)

    if funct_type == "sample":
        if not args.quiet:
            message_proc("\n[+] processed %s hashes with a BGM filter of %s [+]\n" % (sample_data['count'], str(args.filter)), args)
    elif funct_type == "session":
        if not args.quiet:
            message_proc("\n[+] processed %s sessions [+]\n" % sample_data['count'], args)

# Output List Function
# This just returns sample based meta-data based on the query provided
# Intended to be filtered/sorted afterwards by "|" pipe delimited characters

def build_output_string(args, item, type):

    output  = args.output.split(",")

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

        if args.special == "tag_count":
            output = ["tags"]

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
        meta_sections = {
        "application"           : item.application,
        "account_name"          : item.account_name,
        "device_country_code"   : item.device_country_code,
        "device_country"        : item.device_country,
        "device_hostname"       : item.device_hostname,
        "industry"              : item.industry,
        "business_line"         : item.business_line,
        "device_model"          : item.device_model,
        "device_serial"         : item.device_serial,
        "device_version"        : item.device_version,
        "dst_country_code"      : item.dst_country_code,
        "dst_country"           : item.dst_country,
        "dst_ip"                : item.dst_ip,
        "dst_port"              : item.dst_port,
        "email_recipient"       : item.email_recipient,
        "email_charset"         : item.email_charset,
        "email_sender"          : item.email_sender,
        "email_subject"         : item.email_subject,
        "file_name"             : item.file_name,
        "file_url"              : item.file_url,
        "src_country_code"      : item.src_country_code,
        "src_country"           : item.src_country,
        "src_ip"                : item.src_ip,
        "src_port"              : item.src_port,
        "timestamp"             : str(item.timestamp)
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
            message_proc("\n[+] sample_meta [+]\n", args)

        if args.ident == "query":
                for sample in poll_af(args.query):
                    print_line = build_output_string(args, sample, "meta")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        else:
                for sample in poll_af(af_query(args.ident,args.query)):
                    print_line = build_output_string(args, sample, "meta")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        # Count and print only tags
        if args.special == "tag_count":

            tag_count = {}

            for row in results:
                for entry in row:
                    tags = entry.split(",")

                for tag in tags:
                    if tag not in tag_count:
                        tag_count[tag] = 1
                    else:
                        tag_count[tag] += 1

            for tag in tag_count:
                message_proc("%05s | %s" % (tag_count[tag], tag), args)

        else:
            # Auto-adjust column widths
            widths = [max(map(len,col)) for col in zip(*results)]
            for row in results:
                message_proc(" | ".join((val.ljust(width) for val, width in zip(row, widths))), args)

        if not args.quiet:
            message_proc("\n[+] processed %s samples [+]\n" % str(count), args)

    #
    # Session scrape
    #
    if args.run == "session_scrape":

        if research_mode == "True":
            poll_af = AFSession.scan
        else:
            poll_af = AFSession.search

        if not args.quiet:
            message_proc("\n[+] session_meta [+]\n", args)

        if args.ident == "query":
                for session in poll_af(args.query):
                    print_line = build_output_string(args, session, "session")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        else:
                for session in poll_af(af_query(args.ident,args.query)):
                    print_line = build_output_string(args, session, "session")
                    if count < args.limit:
                        results.append(print_line)
                        count += 1
                    else:
                        break

        # Auto-adjust column widths
        widths = [max(map(len,col)) for col in zip(*results)]
        for row in results:
            message_proc(" | ".join((val.ljust(width) for val, width in zip(row, widths))), args)

        if not args.quiet:
            message_proc("\n[+] processed %s sessions [+]\n" % str(count), args)

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
        message_proc("[+] af import query [+]\n", args)

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

    message_proc("%s\n" % import_query, args)

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
        message_proc("[+] yara rule [+]\n", args)

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
        message_proc("%s\n" % yara_sig, args)
    else:
        message_proc("No yara rule could be generated.\n")

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
        "service_scrape",
        "session_scrape",
        "diff",
        "tag_check",
        "tag_info"
    ]
    session_sections = [
        "application",
        "account_name",
        "device_country_code",
        "device_country",
        "device_hostname",
        "industry",
        "business_line",
        "device_model",
        "device_serial",
        "device_version",
        "dst_country_code",
        "dst_country",
        "dst_ip",
        "dst_port",
        "email_recipient",
        "email_charset",
        "email_sender",
        "email_subject",
        "file_name",
        "file_url",
        "src_country_code",
        "src_country",
        "src_ip",
        "src_port",
        "timestamp"
    ]
    sample_sections = [
        "apk_app_icon",
        "apk_cert_file",
        "apk_defined_activity",
        "apk_defined_intent_filter",
        "apk_defined_receiver",
        "apk_defined_sensor",
        "apk_defined_service",
        "apk_digital_signer",
        "apk_embedded_library",
        "apk_embeded_url",
        "apk_internal_file",
        "apk_isrepackaged",
        "apk_name",
        "apk_packagename",
        "apk_requested_permission",
        "apk_sensitive_api_call",
        "apk_suspicious_action_monitored",
        "apk_suspicious_api_call",
        "apk_suspicious_file",
        "apk_suspicious_pattern",
        "apk_suspicious_string",
        "apk_version_num",
        "behavior",
        "behavior_type",
        "connection",
        "default",
        "digital_signer",
        "dns",
        "file",
        "http",
        "imphash",
        "japi",
        "mac_embedded_file",
        "mac_embedded_url",
        "misc",
        "mutex",
        "process",
        "registry",
        "service",
        "summary",
        "user_agent"
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
        "input_file",
        "input_file_query"
    ]
    specials = [
        "yara_rule",
        "af_import",
        "range",
        "count",
        "tag_count",
        "bgm"
    ]
    filter = [
        "suspicious",
        "highly_suspicious"
    ]

    # Grab initial arguments from CLI
    parser = argparse.ArgumentParser(description="Run functions to retrieve information from AutoFocus.")
    parser.add_argument("-i", "--ident", help="Query identifier type for AutoFocus search. [" + ", ".join(identifiers) + "]", metavar='<query_type>', required=True)
    parser.add_argument("-q", "--query", help="Value to query Autofocus for.", metavar='<query>', required=True)
    parser.add_argument("-o", "--output", help="Section of data to return. Multiple values are comma separated (no space) or \"all\" for everything, which is default. "
                                               "Sample Sections [" + ", ".join(sample_sections) + "]. "
                                                                                                  "Session Sections [" + ", ".join(session_sections) + "]. "
                                                                                                                                                       "Meta Sections [" + ", ".join(meta_sections) + "]", metavar='<section_output>', default="all")
    parser.add_argument("-f", "--filter", help="Filter out Benign/Grayware/Malware counts over this number, default 10,000. Use \"suspicious\" and \"highly_suspicious\" for pre-built malware filtering. Use 0 for no filter.", metavar="<number>", default=10000)
    parser.add_argument("-l", "--limit", help="Limit the number of analyzed samples, default 200. Use 0 for no limit.", metavar="<number>", type=int, default=200)
    parser.add_argument("-r", "--run", choices=functions, help="Function to run. [" + ", ".join(functions) + "]", metavar='<function_name>', required=True)
    parser.add_argument("-s", "--special", choices=specials, help="Output data formated in a special way for other tools. [" + ", ".join(specials) + "]", metavar="<special_output>",default=[])
    parser.add_argument("-c", "--commonality", help="Commonality percentage for comparison functions, default is 100", metavar="<integer_percent>", type=int, default=100)
    parser.add_argument("-Q", "--quiet",help="Suppress any informational output and only return data.",action="store_true",default=False)
    parser.add_argument("-w", "--write", help="Write output to a file instead of STDOUT.", metavar='<filename>', default=False)
    args = parser.parse_args()
    args.query = args.query.replace("\\", "\\\\")

    if args.ident == "input_file":
        hashlist = fetch_from_file(args, args.query)
        # Build an AF query using the hash list that was just generated join the list into a comma-separated string, because this is what some other functions expect.
        args.query = af_query("hash_list",",".join(item for item in hashlist))
        args.ident = "query"
    elif args.ident == "input_file_query":
        # Build an AF query using input from a file - helpful for Windows OS users where quotes on CLI are not escaped the same
        args.query = fetch_from_file(args, args.query)
        args.ident = "query"

    # No filter limit
    if args.filter == 0:
        args.filter = 1000000000

    # No sample/session limit
    if args.limit == 0:
        args.limit = 1000000000

    # Gather results from functions
    funct_type = "sample"

    if not args.quiet:
        if args.ident == "query":
            message_proc("\n%s" % args.query, args)
        elif args.run == "tag_check":
            message_proc("\nTag:   %s\nHash:  %s" % (args.query.split(",")[0], args.query.split(",")[1]), args)
        else:
            message_proc("\n%s" % af_query(args.ident, args.query).strip(), args)

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
    elif args.run == "service_scrape":
        out_data = service_scrape(args)
    elif args.run == "meta_scrape" or args.run == "session_scrape":
        out_data = {}
        funct_type = "list"
    elif args.run == "diff":
        out_data = diff(args)
    elif args.run == "tag_check":
        out_data = tag_check(args)
    elif args.run == "tag_info":
        tag_info(args)

    if "count" not in out_data:
        out_data['count'] = 1

    # If we have specified a -s option, do the following
    if "af_import" in args.special or "yara_rule" in args.special:

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
