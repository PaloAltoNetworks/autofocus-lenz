#!/usr/bin/env python
from autofocus import AutoFocusAPI
AutoFocusAPI.api_key = ""
from autofocus import AFSession, AFSample, AFServiceActivity, AFRegistryActivity, AFProcessActivity, AFApiActivity, AFUserAgentFragments, AFMutexActivity, AFHttpActivity, AFDnsActivity, AFBehaviorTypeAnalysis, AFConnectionActivity, AFFileActivity
import sys, argparse, threading, Queue

__version__ = "1.0.2"

##########################
# AF QUERY SECTION BELOW #
##########################

def af_query(input_type,query_value):
    operator_value = "contains"
    if input_type == "ip": # IP Address Field
        field_value = "alias.ip_address"
        #field_value = "sample.tasks.connection"
    elif input_type == "dns": # DNS/Domain Field
        field_value = "alias.domain"
        #field_value = "sample.tasks.dns"
    elif input_type == "hash": # Hash Field
        operator_value = "is"
        if len(query_value) == 32:
            field_value = "sample.md5"
        elif len(query_value) == 40:
            field_value = "sample.sha1"
        elif len(query_value) == 64:
            field_value = "sample.sha256"
    elif input_type == "http":
        field_value = "sample.tasks.http" # HTTP Activity Field
    elif input_type == "file":
        field_value = "sample.tasks.file" # File Activity Field
        query_value = query_value.replace("\\", "\\\\") # Covert 1 '\' to '\\' - double escaping for AF query
    elif input_type == "process":
        field_value = "sample.tasks.process" # Tasks Activity Field
    elif input_type == "mutex":
        field_value = "sample.tasks.mutex" # Mutex Activity Field
    elif input_type == "registry":
        field_value = "sample.tasks.registry" # Registry Activity Field
        query_value = query_value.replace("\\", "\\\\") # Covert 1 '\' to '\\' - double escaping for AF query
    elif input_type == "service":
        field_value = "sample.tasks.service" # Service Activity Field
    elif input_type == "connection":
        field_value = "sample.tasks.connection" # Network/Connection Activity Field
    elif input_type == "user_agent":
        field_value = "sample.tasks.user_agent" # User-Agent Activity Field
        operator_value = "is"
    elif input_type == "tag":
        field_value = "sample.tag"
        operator_value = "is in the list"
    elif input_type == "hash_list":
        field_value = "sample.sha256"
        operator_value = "is in the list"
    else:
        sys.exit(1)
    if input_type == "tag": # Return as an array
        af_search = '{"operator":"all","children":[{"field":"%s","operator":"%s","value":["%s"]}]}' % (field_value, operator_value, query_value)
    elif input_type == "hash_list":
        query_value = query_value.split(",")
        af_search = ('{"operator":"all","children":[{"field":"%s","operator":"%s","value":%s}]}' % (field_value, operator_value, query_value)).replace("\'", "\"")
    else:
        af_search = '{"operator":"all","children":[{"field":"%s","operator":"%s","value":"%s"}]}' % (field_value, operator_value, query_value)
    return af_search

###########################
# FUNCTION SECTIONS BELOW #
###########################

# Hash Library Function
# Builds the hash library which is used by every other function
# Returns data as dictionary with each key being the hash and a dictionary value with each section featuring a list {hash:{section:[value1,value2]}}

def hash_library(ident, query, filter_size):
    hashes = {}
    print "\n[+] hashes [+]\n"
    if ident == "query":
        for sample in AFSample.scan(query):
            hashes[sample.sha256] = {}
    else:
        for sample in AFSample.search(af_query(ident, query)):
            hashes[sample.sha256] = {}
    thread_queue = Queue.Queue()
    for hash in hashes.keys():
        print hash
        hash_thread = threading.Thread(target=hash_lookup, args=(hash, filter_size, thread_queue))
        hash_thread.start()
        hashes[hash] = thread_queue.get()
    return hashes

# Hash Lookup Function
# Basic hash lookup for a sample
# If delimeter is changed, or new fields added to what's provided here, there is a possibility of messing up other functions

def hash_lookup(query, filter_size, thread_queue):
    sample_data = {"service":[],"registry":[],"process":[],"misc":[],"user_agent":[],"mutex":[],"http":[],"dns":[],"behavior_type":[],"connection":[],"file":[]}
    for sample in AFSample.search(af_query("hash", query)):
        for analysis in sample.get_analyses():
            #print "\n".join(["{}={}".format(k,v) for k,v in analysis.__dict__.items()]) # For troubleshooting
            #print "[[***********]]"
            if type(analysis) is AFServiceActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['service'].append(analysis._raw_line)
            if type(analysis) is AFRegistryActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['registry'].append(analysis._raw_line)
            if type(analysis) is AFProcessActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['process'].append(analysis._raw_line)
            if type(analysis) is AFApiActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['misc'].append(analysis._raw_line)
            if type(analysis) is AFUserAgentFragments:
                if analysis.fragment not in sample_data['user_agent']:
                    sample_data['user_agent'].append(analysis._raw_line)
            if type(analysis) is AFMutexActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['mutex'].append(analysis._raw_line)
            if type(analysis) is AFHttpActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['http'].append(analysis._raw_line)
            if type(analysis) is AFDnsActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['dns'].append(analysis._raw_line)
            if type(analysis) is AFBehaviorTypeAnalysis:
                sample_data['behavior_type'].append("%s" % (analysis.behavior))
            if type(analysis) is AFConnectionActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    if "listen" in analysis.action: # Added and submitted bug on the normalization of listen
                        continue
                    else:
                        sample_data['connection'].append(analysis._raw_line)
            if type(analysis) is AFFileActivity:
                if (analysis.benign_count + analysis.grayware_count + analysis.malware_count) < filter_size:
                    sample_data['file'].append(analysis._raw_line)
    thread_queue.put(sample_data)
    return sample_data

# Common Artifacts Function
# Identifies lines that exist, per section, in every identified sample
# Must be a 100% match across all samples to be reported, thus samples that unique every install may not have certain entries appear

def common_artifacts(ident, query, filter_size, commonality):
    commonality = float(commonality)/float(100)
    compare_data = {"service":{},"registry":{},"process":{},"misc":{},"user_agent":{},"mutex":{},"http":{},"dns":{},"behavior_type":{},"connection":{},"file":{}}
    common_data = {"service":[],"registry":[],"process":[],"misc":[],"user_agent":[],"mutex":[],"http":[],"dns":[],"behavior_type":[],"connection":[],"file":[]}
    count = 0
    hashes = hash_library(ident, query, filter_size)
    for hash in hashes.keys():
        hash_data = {"service":{},"registry":{},"process":{},"misc":{},"user_agent":{},"mutex":{},"http":{},"dns":{},"behavior_type":{},"connection":{},"file":{}}
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
                common_data[section].append(value)
    common_data['count'] = count # Keep track of how many samples processed
    return common_data

# Common Pieces Function
# Similar to the "comnmon_artifact" function, but further breaks down each line to look for commonalities
# Will have more hits but likely less accurate

def common_pieces(ident, query, filter_size, commonality):
    commonality = float(commonality)/float(100)
    compare_data = {"service":{},"registry":{},"process":{},"misc":{},"user_agent":{},"mutex":{},"http":{},"dns":{},"behavior_type":{},"connection":{},"file":{}}
    common_pieces = {"service":[],"registry":[],"process":[],"misc":[],"user_agent":[],"mutex":[],"http":[],"dns":[],"behavior_type":[],"connection":[],"file":[]}
    count = 0
    hashes = hash_library(ident, query, filter_size)
    for hash in hashes.keys():
        hash_data = {"service":{},"registry":{},"process":{},"misc":{},"user_agent":{},"mutex":{},"http":{},"dns":{},"behavior_type":{},"connection":{},"file":{}}
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
                common_pieces[section].append(value)
    common_pieces['count'] = count # Keep track of how many samples processed
    return common_pieces

# Unique Sessions Function
# Will gather session data from the identified samples and then report back the unique values per section
# Session data isn't normalized quite the same as sample data so this may be more error-prone

def uniq_sessions(ident, query):
    session_data = {"subject":[],"filename":[],"application":[],"country":[],"industry":[],"email":[]}
    count = 0
    if ident == "query":
        query = query
    else:
        query = af_query(ident, query)
    for session in AFSession.scan(query):
        subject, filename, application, country, industry, email = session.email_subject, session.file_name, session.application, session.dst_country, session.industry, session.email_sender
        if subject not in session_data['subject'] and subject:
            session_data['subject'].append(subject)
        if filename not in session_data['filename'] and filename:
            session_data['filename'].append(filename)
        if application not in session_data['application'] and application:
            session_data['application'].append(application)
        if country not in session_data['country'] and country:
            session_data['country'].append(country)
        if industry not in session_data['industry'] and industry:
            session_data['industry'].append(industry)
        if email not in session_data['email'] and email:
            session_data['email'].append(email)
        count += 1
    session_data['count'] = count
    return session_data

# HTTP Scraper Function
# Extracts all HTTP requests made from the identified samples
# BGM filtering is done on the entire line and not just the URL, so it won't be as precise

def http_scrape(ident, query, filter_size):
    http_data = {"http":[]}
    count = 0
    hashes = hash_library(ident, query, filter_size)
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
# BGM filtering is done on the entire line and not just the URL, so it won't be as precise

def dns_scrape(ident, query, filter_size):
    dns_data = {"dns":[]}
    count = 0
    hashes = hash_library(ident, query, filter_size)
    for hash in hashes.keys():
        sample_data = hashes[hash]
        for entry in sample_data['dns']:
            dns_list = entry.split(" , ")
            dns_query = dns_list[0]
            if dns_query not in dns_data['dns']:
                        dns_data['dns'].append(dns_query)
        count += 1
    dns_data['count'] = count # Keep track of how many samples processed
    return dns_data

# Mutex Scraper Function
# Extracts all mutexes created within the identified samples
# BGM filtering is done on the entire line and not just the URL, so it won't be as precise

def mutex_scrape(ident, query, filter_size):
    mutex_data = {"mutex":[]}
    count = 0
    hashes = hash_library(ident, query, filter_size)
    for hash in hashes.keys():
        sample_data = hashes[hash]
        for entry in sample_data['mutex']:
            mutex_list = entry.split(" , ")
            mutex_value = mutex_list[2]
            if mutex_value not in mutex_data['mutex']:
                        mutex_data['mutex'].append(mutex_value)
        count += 1
    mutex_data['count'] = count # Keep track of how many samples processed
    return mutex_data

########################
# OUTPUT SECTION BELOW #
########################

# Output Analysis Function
# This is what gets printed out to the screen
# Takes a normalized input of sections and returns the sections requested by the user

def output_analysis(output, sample_data, filter, funct_type):
    output = output.split(",")
    # SESSIONS: subject, filename, application, country, industry, email
    # SAMPLES: service, registry, process, misc, user_agent, mutex, http, dns, behavior_type, connection, file
    section_list = ["service", "registry", "process", "misc", "user_agent", "mutex", "http", "dns", "behavior_type", "connection", "file", "subject", "filename", "application", "country", "industry", "email"]
    if "all" in output:
        for entry in section_list:
            if entry in sample_data.keys():
                print "\n[+]", entry, "[+]\n"
                for value in sample_data[entry]:
                    if value != "":
                        print value
    else:
        for entry in output:
            if sample_data[entry]:
                print "\n[+]", entry, "[+]\n"
                for value in sample_data[entry]:
                    if value != "":
                        print value
    if funct_type == "sample":
        print "\n[+] processed", sample_data['count'], "hashes with a BGM filter of", str(filter), "[+]\n"
    elif funct_type == "session":
        print "\n[+] processed", sample_data['count'], "sessions [+]\n"

# AutoFocus Import Function
# Builds a query for import into AutoFocus based on returned results
# AutoFocus API has a limit on the lines allowed and too many results will make it more challenging to manage in the portal

def af_import(output, sample_data):
    # Initialize some values
    output = output.split(",")
    if "all" in output:
        output = []
        for key in sample_data.keys():
            output.append(key)
    # Build AutoFocus query
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

def yara_rule(output, sample_data):
    # Initialize some values
    output = output.split(",")
    if "all" in output:
        output = []
        for key in sample_data.keys():
            output.append(key)
    print "[+] yara sig [+]\n"
    min_len = 4 # Minimum string length
    contained_list = []
    entry_list = []
    # Build yara rule
    yara_sig = "rule generated_by_afIR\n{\n\tstrings:\n"
    for entry in output:
        if entry in sample_data.keys() and entry == "dns":
            count = 0
            for value in sample_data[entry]:
                dns_entry = value.split(" , ")[0]
                dns_resolve = value.split(" , ")[1]
                if dns_entry not in contained_list and dns_entry != "" and len(dns_entry) > min_len:
                    entry_list.append("dns")
                    contained_list.append(dns_entry)
                    yara_sig += "\t\t$dns_" + str(count) + " = \"" + dns_entry + "\"\n" # Just grab the domain
                if dns_resolve not in contained_list and dns_resolve != "" and len(dns_resolve) > min_len:
                    entry_list.append("dns")
                    contained_list.append(dns_resolve)
                    yara_sig += "\t\t$dns_" + str(count+1) + " = \"" + dns_resolve + "\"\n" # Just grab the resolved IP
                count += 2
        if entry in sample_data.keys() and entry == "http":
            count = 0
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
                    yara_sig += "\t\t$http_" + str(count) + " = \"" + domain_name + "\"\n" # Just grab the domain
                if url_path not in contained_list and url_path != "" and len(url_path) > min_len:
                    entry_list.append("http")
                    contained_list.append(url_path)
                    yara_sig += "\t\t$http_" + str(count+1) + " = \"" + url_path + "\"\n" # Just grab the URL path
                if full_ua not in contained_list and full_ua != "" and len(full_ua) > min_len:
                    entry_list.append("http")
                    contained_list.append(full_ua)
                    yara_sig += "\t\t$http_" + str(count+2) + " = \"" + full_ua + "\"\n" # Just grab the full user-agent
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
            for value in sample_data[entry]:
                mutex_name = value.split(" , ")[2]
                if mutex_name not in contained_list and mutex_name != "" and mutex_name not in mutex_blacklist and len(mutex_name) > min_len: # Just grab mutex name
                    entry_list.append("mutex")
                    contained_list.append(mutex_name)
                    yara_sig += "\t\t$mutex_" + str(count) + " = \"" + mutex_name + "\"\n"
                count += 1
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
    else:
        print "No yara rule could be generated.\n"

################
# MAIN PROGRAM #
################

def main():
    # Set initial values
    functions = ["uniq_sessions", "hash_lookup", "common_artifacts", "common_pieces", "http_scrape", "dns_scrape", "mutex_scrape"]
    sections = ["service", "registry", "process", "misc", "user_agent", "mutex", "http", "dns", "behavior_type", "connection", "file", "subject", "filename", "application", "country", "industry", "email"]
    identifiers = ["hash", "hash_list", "ip", "network", "dns", "file", "http", "mutex", "process", "registry", "service", "user_agent", "tag", "query"]
    specials = ["yara_rule", "af_import"]
    # Grab initial arguments from CLI
    parser = argparse.ArgumentParser(description="Run functions to retrieve information from AutoFocus.")
    parser.add_argument("-i", "--ident", help="Query identifier type for AutoFocus search. [" + ", ".join(identifiers) + "]", metavar='<query_type>', required=True)
    parser.add_argument("-q", "--query", help="Value to query Autofocus for.", metavar='<query>', required=True)
    parser.add_argument("-o", "--output", help="Section of data to return. Multiple values are comma separated (no space) or \"all\" for everything, which is default. [" + ", ".join(sections) + "]", metavar='<section_output>', default="all")
    parser.add_argument("-f", "--filter", help="Filter out Benign/Grayware/Malware counts over this number, default 10,000.", metavar="<number>", type=int, default=10000)
    parser.add_argument("-r", "--run", choices=functions, help="Function to run. [" + ", ".join(functions) + "]", metavar='<function_name>', required=True)
    parser.add_argument("-s", "--special", choices=specials, help="Output data formated in a special way for other tools. [" + ", ".join(specials) + "]", metavar="<special_output>")
    parser.add_argument("-c", "--commonality", help="Commonality percentage for comparison functions, default is 100", metavar="<integer_percent>", type=int, default=100)
    args = parser.parse_args()
    # Gather results from functions
    funct_type = "sample"
    if args.ident == "query":
        print "\n", args.query
    else:
        print "\n" + af_query(args.ident, args.query).strip()
    if args.run == "uniq_sessions":
        out_data = uniq_sessions(args.ident, args.query)
        funct_type = "session"
    elif args.run == "hash_lookup":
        out_data = hash_library(args.ident, args.query, args.filter)[args.query] # Pull itself out of the hash library
    elif args.run == "common_artifacts":
        out_data = common_artifacts(args.ident, args.query, args.filter, args.commonality)
    elif args.run == "common_pieces":
        out_data = common_pieces(args.ident, args.query, args.filter, args.commonality)
    elif args.run == "http_scrape":
        out_data = http_scrape(args.ident, args.query, args.filter)
    elif args.run == "dns_scrape":
        out_data = dns_scrape(args.ident, args.query, args.filter)
    elif args.run == "mutex_scrape":
        out_data = mutex_scrape(args.ident, args.query, args.filter)
    # Output results to console
    if "count" not in out_data:
        out_data['count'] = 1
    output_analysis(args.output, out_data, args.filter, funct_type)
    if args.special == "af_import":
        af_import(args.output, out_data)
    elif args.special == "yara_rule":
        yara_rule(args.output, out_data)

if __name__ == '__main__':
    main()
