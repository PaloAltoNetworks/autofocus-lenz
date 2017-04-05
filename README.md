## af_lenz

### [+] INTRO [+]

The AutoFocus API exposes a wealth of dynamic analysis information about malware activities from disk to wire, which is made easily accessible for scripting through the [AutoFocus Python Client Library](https://github.com/PaloAltoNetworks/autofocus-client-library). The goal of *af_lenz.py* is to build ontop of the client library by providing a set of helpful tools to aide incident responders, or analysts, in rapidly extracting information from AutoFocus that can be used for operational intelligence.

```
$ python af_lenz.py --help
usage: af_lenz.py [-h] -i <query_type> -q <query> [-o <section_output>]
                  [-f <number>] [-l <number>] -r <function_name>
                  [-s <special_output>] [-c <integer_percent>] [-Q]
                  [-w <filename>]

Run functions to retrieve information from AutoFocus.

optional arguments:
  -h, --help            show this help message and exit
  -i <query_type>, --ident <query_type>
                        Query identifier type for AutoFocus search. [hash,
                        hash_list, ip, connection, dns, file, http, mutex,
                        process, registry, service, user_agent, tag, query,
                        input_file, input_file_query]
  -q <query>, --query <query>
                        Value to query Autofocus for.
  -o <section_output>, --output <section_output>
                        Section of data to return. Multiple values are comma
                        separated (no space) or "all" for everything, which is
                        default. Sample Sections [apk_app_icon, apk_cert_file,
                        apk_certificate_id, apk_defined_activity,
                        apk_defined_intent_filter, apk_defined_receiver,
                        apk_defined_sensor, apk_defined_service,
                        apk_digital_signer, apk_embedded_library,
                        apk_embeded_url, apk_internal_file, apk_isrepackaged,
                        apk_name, apk_packagename, apk_requested_permission,
                        apk_sensitive_api_call,
                        apk_suspicious_action_monitored,
                        apk_suspicious_api_call, apk_suspicious_file,
                        apk_suspicious_pattern, apk_suspicious_string,
                        apk_version_num, behavior, behavior_type, connection,
                        digital_signer, dns, file, http, imphash, japi,
                        mac_embedded_file, mac_embedded_url, misc, mutex,
                        process, registry, service, summary, user_agent].
                        Session Sections [application, account_name,
                        device_country_code, device_country, device_hostname,
                        industry, business_line, device_model, device_serial,
                        device_version, dst_country_code, dst_country, dst_ip,
                        dst_port, email_recipient, email_charset,
                        email_sender, email_subject, file_name, file_url,
                        src_country_code, src_country, src_ip, src_port,
                        timestamp]. Meta Sections [sha256, file_type,
                        create_date, verdict, file_size, tags, sha1, md5,
                        ssdeep, imphash, digital_signer]
  -f <number>, --filter <number>
                        Filter out Benign/Grayware/Malware counts over this
                        number, default 10,000. Use "suspicious" and
                        "highly_suspicious" for pre-built malware filtering.
                        Use 0 for no filter.
  -l <number>, --limit <number>
                        Limit the number of analyzed samples, default 200. Use
                        0 for no limit.
  -r <function_name>, --run <function_name>
                        Function to run. [uniq_sessions, common_artifacts,
                        common_pieces, hash_scrape, http_scrape, dns_scrape,
                        mutex_scrape, meta_scrape, service_scrape,
                        session_scrape, diff, tag_check, tag_info]
  -s <special_output>, --special <special_output>
                        Output data formated in a special way for other tools.
                        [yara_rule, af_import, range, count, tag_count, bgm]
  -c <integer_percent>, --commonality <integer_percent>
                        Commonality percentage for comparison functions,
                        default is 100
  -Q, --quiet           Suppress any informational output and only return
                        data.
  -w <filename>, --write <filename>
                        Write output to a file instead of STDOUT.
```

Quick links to examples:
* [Hash Scrape function](#hash_scrape)
* [Common Artifacts function](#common_artifacts)
* [Common Pieces function](#common_pieces)
* [Show commonality range](#range)
* [HTTP Scrape function](#http_scrape)
* [DNS Scrape function](#dns_scrape)
* [Mutex Scrape function](#mutex_scrape)
* [Unique Sessions function](#uniq_sessions)
* [Generate Yara rule](#yara_rule)
* [Generate AutoFocus query](#af_import)
* [Control output](#section_output)
* [Set commonality percent](#commonality)
* [Submit complex AutoFocus queries](#complex_query)
* [Analyze non-PE files](#apk_analyzer)
* [Limit analyzed samples](#limit_result)
* [Collect bulk sample meta data](#meta_data)
* [Extract all unique entries](#extract_all)
* [Quiet Output](#quiet_flag)
* [Diff function](#diff)
* [Count function](#count)
* [Tag Count function](#tag_count)
* [Suspicious/Highly Suspicious filter](#suspect_artifacts)
* [Service Scrape function](#service_scrape)
* [Write to file](#write_out)
* [Tag Info](#tag_info)
* [Tag Check](#tag_check)

### [+] EXAMPLES [+]

Analyzing activity of malware can be very noisy and AutoFocus provides a good way to identify whether something might be noise through the use of the B/G/M system. For each sample with a matching entry for the activity, whether its file, network, or process based, it will be added to a count for benign, grayware, and malicious samples. In this fashion, if a entry has 5 million matches to benign samples, it's likely just noise; that being said, *af_lenz.py* has a built-in filter of 10,000 matches but can be adjusted with the *-f* flag to override it.

To lookup the dynamic analysis (DA) information for a particular sample, specify the identifier for the query as hash, pass the SHA256 hash, and run the "hash_lookup" function. As you'll see, it can be a large amount of data, pipe delimeted, but gives you a quick way to automate or hone in on specifics.

##### hash_scrape

```
python af_lenz.py -i hash -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d -r hash_scrape

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d

[+] registry [+]

sample.exe , SetValueKey , HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\Windows Audio Service , Value:Windows\SysWOW64\svchost_update.exe , Type:1
svchost_update.exe , DeleteValueKey , HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass
svchost_update.exe , DeleteValueKey , HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass
svchost_update.exe , DeleteValueKey , HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\IntranetName
    <TRUNCATED>
ntsystem.exe , RegCreateKeyEx , HKLM , System\CurrentControlSet\Services\Tcpip\Parameters
netsh.exe , RegSetValueEx , HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List , WINDOWS\system32\ntsystem.exe , WINDOWS\system32\ntsystem.exe:*:Enabled:Windows ClipBook
ntsystem.exe , RegSetValueEx , HKCU\Software\pb , id , 1494421186
ntsystem.exe , RegSetValueEx , HKCU\Software\pb , hl , aHR0cDovL21pYmVycG9ydGVzYWwuY29tL2dvLnBocA==

[+] process [+]

sample.exe , created ,  , Windows\SysWOW64\svchost_update.exe ,  Windows\SysWOW64\svchost_update.exe
svchost_update.exe , created ,  , Windows\SysWOW64\netsh.exe ,  Windows\System32\netsh.exe  firewall add allowedprogram  Windows\SysWOW64\svchost_update.exe   Windows Audio Service  ENABLE
svchost_update.exe , terminated ,  , Windows\SysWOW64\netsh.exe
unknown , terminated ,  , Windows\SysWOW64\svchost_update.exe
    <TRUNCATED>
ntsystem.exe , LoadLibraryExW , DNSAPI.dll ,  , 0
ntsystem.exe , LoadLibraryExW , rasadhlp.dll ,  , 0
ntsystem.exe , LoadLibraryExW , hnetcfg.dll ,  , 0
ntsystem.exe , LoadLibraryExW , WINDOWS\System32\wshtcpip.dll ,  , 0

[+] misc [+]

svchost_update.exe , SetWindowLong , SystemProcess , GWL_WNDPROC
svchost_update.exe , IsDebuggerPresent
ntsystem.exe , SetWindowLong , SystemProcess , GWL_WNDPROC

[+] mutex [+]

svchost_update.exe , CreateMutexW , Local\!IETld!Mutex
ntsystem.exe , CreateMutexW , c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
ntsystem.exe , CreateMutexW , c:!documents and settings!administrator!cookies!
ntsystem.exe , CreateMutexW , c:!documents and settings!administrator!local settings!history!history.ie5!
ntsystem.exe , CreateMutexW , WininetConnectionMutex
ntsystem.exe , CreateMutexW , <NULL>

[+] http [+]

markovqwesta.com , GET , /que.php , pb
93.189.40.225 , GET , /wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW ,

[+] dns [+]

markovqwesta.com , 193.235.147.11 , A
iholpforyou4.com ,  , NXDOMAIN
markovqwesta.com , ns4.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] behavior_desc [+]

informational , 0.1 , A process running on the system may start additional processes to perform actions in the background. This behavior is common to legitimate software as well as malware. , process , 6 , Started a process
medium , 0.4 , Legitimate software typically uses well-known application protocols to communicate over a network. In some cases, however, legitimate software may use proprietary protocols. Malware commonly uses custom protocols to avoid detection, and a sample that generates unknown TCP or UDP traffic in this way is often malicious. , unknown_traffic , 7 , Generated unknown TCP or UDP traffic
high , 0.45 , Malware typically communicates back to an attacker via a command-and-control server. This command-and-control server is usually addressed in the malware as a domain name. To avoid easy identification of malicious domain names, the attacker may use a domain generation algorithm (DGA) to address a large number of dynamically generated domains, most of which are not registered. , nx_domain , 8 , Connected to an unregistered domain name
informational , 0.1 , The Windows Registry houses system configuration settings and options, including information about installed applications, services, and drivers. Malware often modifies registry data to establish persistence on the system and avoid detection. , registry , 13 , Modified the Windows Registry
    <TRUNCATED>
high , 0.45 , The Windows system folder contains configuration files and executables that control the underlying functions of the system. Malware often places executables in this folder to avoid detection. , sys_exe , 34 , Created an executable file in the Windows system folder
low , 0.3 , User folders are storage locations for music, pictures, downloads, and other user-specific files. Legitimate applications rarely place executable content in these folders, while malware often does so to avoid detection. , create_doc_exe , 35 , Created an executable file in a user folder
medium , 0.4 , Windows services are background applications that are typically invisible to users. Unlike processes, services can run when no user is logged on. Malware often installs services to establish persistence on the system, or as a precursor to loading malicious device drivers. , install_service , 37 , Installed a Windows service
medium , 0.45 , Most legitimate HTTP connections are established using a hostname, which is ultimately resolved to an IP address. Malware often connects directly to an IP address to avoid hostname-based blocking. , http_direct_ip , 86 , Connected directly to an IP address over HTTP

[+] behavior_type [+]

process
unknown_traffic
nx_domain
registry
    <TRUNCATED>
sys_exe
create_doc_exe
install_service
http_direct_ip

[+] connection [+]

unknown , tcp , 193.235.147.11:80 , SE
ntsystem.exe , tcp-connection , 93.189.40.225:80 ,  , RU
ntsystem.exe , tcp-connection , 193.235.147.11:80 ,  , SE
ntsystem.exe , tcp-connection , 46.165.222.212:9505 ,  , DE
ntsystem.exe , tcp-connection , 46.165.222.212:495 ,  , DE

[+] file [+]

sample.exe , Write , Windows\SysWOW64\9125y5yta.dat
sample.exe , Create , Windows\SysWOW64\svchost_update.exe , 00130197 , 00000044
sample.exe , Write , Windows\SysWOW64\svchost_update.exe
svchost.exe , Write , Windows\System32\wdi\{86432a0b-3c7d-4ddf-a89c-172faa90485d}\{d873ef00-5982-4c2b-8a78-ea57c88fbba1}\snapshot.etl
    <TRUNCATED>
unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temp\df4.tmp.exe , md5=1197f290bae092c70a6cf07a223ed8bc , sha1=5e9a3cc80ea4d2b0b31d2a7e8750cd5f1ce16dc7 , sha256=4adb44b3cd6fe503d218067307302628c3a0a895acfe03998c24c8f3d561dd15
unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\LDKH2A5D\book[2].htm , md5=ff4e1927bdf5ad3c6e752a8cb02db5d5 , sha1=ac473bd177e1e9ca7ef74d92eb4a9392bcc4a31e , sha256=4677cb12006da7721110ebc6b763ceb52eaf3e516540f57a7704c6aaea76bc79
unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[2].htm
unknown , delete , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\K1XHOOEA\book[1].htm , md5=ff4e1927bdf5ad3c6e752a8cb02db5d5 , sha1=ac473bd177e1e9ca7ef74d92eb4a9392bcc4a31e , sha256=4677cb12006da7721110ebc6b763ceb52eaf3e516540f57a7704c6aaea76bc79

[+] processed 1 hashes with a BGM filter of 10000 [+]
```

You can also use the *-o* flag to specify only the sections of output you're interested in.

##### section_output

```
python af_lenz.py -i hash -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d -r hash_scrape -o http,dns,connection

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d

[+] http [+]

markovqwesta.com , GET , /que.php , pb
93.189.40.225 , GET , /wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW ,

[+] dns [+]

markovqwesta.com , 193.235.147.11 , A
iholpforyou4.com ,  , NXDOMAIN
markovqwesta.com , ns4.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] connection [+]

unknown , tcp , 193.235.147.11:80 , SE
ntsystem.exe , tcp-connection , 93.189.40.225:80 ,  , RU
ntsystem.exe , tcp-connection , 193.235.147.11:80 ,  , SE
ntsystem.exe , tcp-connection , 46.165.222.212:9505 ,  , DE
ntsystem.exe , tcp-connection , 46.165.222.212:495 ,  , DE

[+] processed 1 hashes with a BGM filter of 10000 [+]
```

Using the previous data, we see an HTTP request that looks interesting and want to investigate further. It can be very cumbersome to go through multiple samples, so the "common_artifacts" function can be run to compare every sample and report back only items that exist across the set. For this query, we are matching any samples that contain the domain in question.

##### common_artifacts

```
python af_lenz.py -i http -q markovqwesta.com -r common_artifacts

{"operator":"all","children":[{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
c550a0730c9cf10751a3236ef57fafb5af844bef3874855a215519a9ffcec348
    <TRUNCATED>
234203c3e40184c430331c266b4108db94b3f68258410b7592da81d6abc88b7d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099

[+] dns [+]

markovqwesta.com , ns4.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] processed 10 hashes with a BGM filter of 10000 [+]
```

One problem with DA is that, by its very nature, its dynamic and has the potential to provide inconsistent results - malware may not run due to certain features being enabled, software being installed, so on and so forth. Continuing with the previous example, instead of a 100% match across all samples, we'll loosen it up to matches across 70% of the set.

##### commonality

```
python af_lenz.py -i http -q markovqwesta.com -r common_artifacts -c 70

{"operator":"all","children":[{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
c550a0730c9cf10751a3236ef57fafb5af844bef3874855a215519a9ffcec348
    <TRUNCATED>
234203c3e40184c430331c266b4108db94b3f68258410b7592da81d6abc88b7d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099

[+] user_agent [+]

pb

[+] http [+]

markovqwesta.com , GET , /que.php , pb

[+] dns [+]

markovqwesta.com , 193.235.147.11 , A
markovqwesta.com , ns4.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] connection [+]

unknown , tcp , 193.235.147.11:80 , SE

[+] processed 10 hashes with a BGM filter of 10000 [+]
```

The "common_pieces" function, which is the similar to the "common_artifacts" function, further breaks up each entry into individual pieces. This is beneficial when malware might inject into random processes or use unique names each time that won't match across samples. All comparison functions can use the *-c* flag to specify the commonality match percentage. In this next query we are search for common pieces for samples matching the Unit 42 Locky tag with a commonality match of 90%.

##### common_pieces

```
python af_lenz.py -i tag -q Unit42.Locky -r common_pieces -c 90

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]}]}

[+] hashes [+]

e720f917cd8a02b0372b85068844e132c42ea2c97061b81d378b5a73f9344003
a486ff7e775624da2283ede1d3959c784afe476b0a69ce88cd12c7238b15c9e6
3297f99631c92aeb7b5fcccfac1c0b0e54880e399cf10a659b4448e6fe339f9d
7f540e391b55221f7696031471b6f8d2068677a67ed8782d52a67872096d23a2
    <TRUNCATED>
1d8cc4e8416b5ac16864583e8bb0d8f8d8ad4b32de7de111067c38da0cfc57b1
a4770e01d7734498834cc80f762890f332f1156198990b46217f63aa5b916030
13bd70822009e07f1d0549e96b8a4aec0ade07bea2c28d42d782bacc11259cf5
b7a593e6b7813d9fc40f435ffe9b080cd0975b05bc47f1e733870fc0af289fdd

[+] registry [+]

HKCU\Software\Locky\pubkey
completed
pubkey
HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\LastServiceStart
    <TRUNCATED>
paytext
HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache\WINDOWS\system32\shimgvw.dll
HKCU\Software\Locky\completed
WallpaperStyle

[+] process [+]

Windows\system32\NOTEPAD.EXE
Windows\System32\taskeng.exe
 rundll32.exe  WINDOWS\system32\shimgvw.dll
142E1D688EF0568370C37187FD9F2351D7DDEDA574F8BFA9B0FA4EF42DB85AA2
    <TRUNCATED>
CreateProcessInternalW
F2C7BB8ACC97F92E987A2D4087D021B1
WINDOWS\system32\rundll32.exe
terminated

[+] http [+]

/main.php
POST

[+] behavior_type [+]

autostart
open_process_dup_handle
http_post
pending_file_rename
    <TRUNCATED>
process
file
registry
create_doc_exe

[+] connection [+]

tcp
unknown

[+] file [+]

C:\Documents and Settings\Administrator\Desktop\_Locky_recover_instructions.txt
Documents and Settings\All Users\Documents\My Pictures\Sample Pictures\Blue hills.jpg
Documents and Settings\Administrator\Cookies\_Locky_recover_instructions.txt
Documents and Settings\All Users\Start Menu\Programs\Startup\_Locky_recover_instructions.txt
    <TRUNCATED>
000900a8
00000060
0011c017
Users\Public\Pictures\Sample Pictures\Chrysanthemum.jpg

[+] processed 1364 hashes with a BGM filter of 10000 [+]
```

There is also a special output for the commonality functions, called "range", which prints out the percentage of commonality. For example, if you set a lower commonality requirement, you can see in which bands of commonality artifacts fall. This may be useful of identifying trends in subsets of the samples or how strong an artifact might be.

##### range

```
python af_lenz.py -i dns -q markovqwesta.com -r common_artifacts -c 30 -s range

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

639d03fb6465a94189fb5b29887afe0965a95c9a7778fb624b92eef6ed22b7bb
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
    <TRUNCATED>
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099
ffe9fb1f9ef7465c99edfe17ccce496172cba47357b2caff6720900a0f6426b2
c97bd3d159222bfe650647aefb92fd13b2e590f8d5dd5781110a0cf61958fc33

[+] registry [+]

33  | sample.exe , SetValueKey , HKCU\Software\kg\cat ,
33  | sample.exe , DeleteValueKey , HKCU\Software\kg\chk ,
33  | sample.exe , DeleteValueKey , HKCU\Software\kg\main ,
33  | sample.exe , SetValueKey , HKCU\Software\kg\chk ,
    <TRUNCATED>
33  | sample.exe , DeleteValueKey , HKCU\Software\kg\main
33  | sample.exe , RegCreateKeyEx , HKCU , SOFTWARE\kg
33  | sample.exe , DeleteValueKey , HKCU\Software\kg\name
33  | sample.exe , DeleteValueKey , HKCU\Software\kg\chk

[+] user_agent [+]

66  | pb

[+] mutex [+]

33  | sample.exe , CreateMutexW , PB_SN_MUTEX_GL_F348B3A2387

[+] http [+]

75  | markovqwesta.com , GET , /que.php , pb

[+] dns [+]

75  | markovqwesta.com , 193.235.147.11 , A
83  | markovqwesta.com , ns4.cnmsn.com , NS
83  | markovqwesta.com , ns3.cnmsn.com , NS

[+] behavior_desc [+]

100 | informational , 0.1 , The Windows Registry houses system configuration settings and options, including information about installed applications, services, and drivers. Malware often modifies registry data to establish persistence on the system and avoid detection. , registry , 13 , Modified the Windows Registry
100 | informational , 0.1 , Legitimate software creates or modifies files to preserve data across system restarts. Malware may create or modify files to deliver malicious payloads or maintain persistence on a system. , file , 3 , Created or modified a file
75  | medium , 0.4 , Windows services are background applications that are typically invisible to users. Unlike processes, services can run when no user is logged on. Malware often installs services to establish persistence on the system, or as a precursor to loading malicious device drivers. , install_service , 37 , Installed a Windows service
58  | high , 0.8 , The Windows Registry Run keys allow an application to specify that it should be launched during system startup. Malware often leverages this mechanism to ensure that it will be run each time the system boots up, and may run content out of a user folder to avoid detection. , autostart_from_local_dir , 77 , Modified the Windows Registry to enable auto-start for a file in a user folder
    <TRUNCATED>
100 | medium , 0.4 , The Windows Registry Run keys allow an application to specify that it should be launched during system startup. Malware often leverages this mechanism to establish persistence on the system and ensure that it will be run each time the system boots up. , autostart , 14 , Modified the Windows Registry to enable auto-start
66  | medium , 0.4 , Legitimate software typically uses well-known application protocols to communicate over a network. In some cases, however, legitimate software may use proprietary protocols. Malware commonly uses custom protocols to avoid detection, and a sample that generates unknown TCP or UDP traffic in this way is often malicious. , unknown_traffic , 7 , Generated unknown TCP or UDP traffic
91  | low , 0.2 , Rather than communicate directly with a server, a client may route requests through a proxy. If the proxy is malicious, it may modify what a user sees when accessing web pages or even execute a man-in-the-middle (MITM) attack, potentially gaining access to sensitive user information. , browser_proxy , 49 , Modified proxy settings for Internet Explorer
58  | medium , 0.45 , Malware analysis environments have a limited amount of time in which to execute code and deliver a verdict. To subvert this process, malware often delays execution, or "sleeps," for a long period, allowing it to avoid detection. , long_sleep , 84 , Attempted to sleep for a long period

[+] behavior_type [+]

50  | external_netsh
33  | http_short_headers
50  | process
50  | file
    <TRUNCATED>
41  | delete_itself
41  | ie_security
50  | create_doc_exe
50  | unpack_write_section

[+] connection [+]

66  | unknown , tcp , 193.235.147.11:80 , SE

[+] file [+]

33  | unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[2].htm
33  | sample.exe , Write , Windows\SysWOW64\9125y5yta.dat
33  | unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[1].htm , md5=46788efce76ebf3e09fc844af99c5309 , sha1=d25ec96232263c0eb834d9c7b437dbe97029a809 , sha256=3376bb271f1e1e7b2e0eb28475f8bab01ed69627861682ac809a732cb023d230
33  | sample.exe , Write , WINDOWS\system32\9125y5yta.dat ,

[+] processed 12 hashes with a BGM filter of 10000 [+]
```

In addition to the comparison functions, there are scraping functions which will iterate over each sample identified and return all unique data in their respective sections. Below are all HTTP requests made by samples with a IP in their DNS section (resolved to).

##### http_scrape

```
python af_lenz.py -i dns -q 193.235.147.11 -r http_scrape

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"193.235.147.11"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e
75e14aaef0ff2b851ce9775a95a1f54624030786134faf29c0e80a675b9c310e
    <TRUNCATED>
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099
118577d6c021c14cbd9c7226475c982d2ce230568295b86f3104860e544f7317

[+] http [+]

hxxp://markovqwesta.com/que.php
hxxp://93.189.40.225/wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW
hxxp://iholpforyou4.com/d_index.php
hxxp://80.78.242.47/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW
    <TRUNCATED>
hxxp://80.78.242.47/pointer.php?proxy=194.247.12.49%3A27123&secret=BER5w4evtjszw4MBRW
hxxp://80.78.242.47/pointer.php?proxy=69.64.32.110%3A23622&secret=BER5w4evtjszw4MBRW
hxxp://93.189.40.196/i.php?proxy=46.38.51.49%3A32045&secret=BER5w4evtjszw4MBRW
hxxp://66.85.139.195/phinso.php?proxy=46.165.222.212%3A29786&secret=BER5w4evtjszw4MBRW

[+] processed 17 hashes with a BGM filter of 10000 [+]
```

DNS scrape of three hashes pasted as a comma separated list.

##### dns_scrape

```
python af_lenz.py -i hash_list -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d,cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03,e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e -r dns_scrape

{"operator":"all","children":[{"field":"sample.sha256","operator":"is in the list","value":["232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d", "cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03", "e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e"]}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e

[+] dns [+]

markovqwesta.com
iholpforyou4.com
truedonell.com

[+] processed 3 hashes with a BGM filter of 10000 [+]
```

Mutex scrape of the same three hashes.

##### mutex_scrape

```
python af_lenz.py -i hash_list -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d,cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03,e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e -r mutex_scrape

{"operator":"all","children":[{"field":"sample.sha256","operator":"is in the list","value":["232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d", "cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03", "e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e"]}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
e4b35695fdf6583ca382647bf4587a2ca225cabf9aa7c954489414ea4f433a9e

[+] mutex [+]

Local\!IETld!Mutex
c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
c:!documents and settings!administrator!cookies!
c:!documents and settings!administrator!local settings!history!history.ie5!
WininetConnectionMutex
<NULL>
IESQMMUTEX_0_208
PB_SN_MUTEX_GL_F348B3A2387
PB_MAIN_MUTEX_GL_63785462387
PB_SCH_MUTEX_GL_A58B78398f17

[+] processed 3 hashes with a BGM filter of 10000 [+]
```

Another common use-case might be to look at the session data related to how malware was delivered. By using the "uniq_session" function, you can view the session data attached to the samples in AutoFocus. In this query, we search for samples matching a unique mutex and pull back their session data.

##### uniq_sessions

```
python af_lenz.py -i mutex -q M_Test -r uniq_sessions

{"operator":"all","children":[{"field":"sample.tasks.mutex","operator":"contains","value":"M_Test"}]}

[+] filename [+]

82300c42-320c-4348-afa7-39abb7f1d5f2_a945e5bc9ca9f26be7315f3dd5beae8a89777c7830a466bcc45c06011ab2b903
a945e5bc9ca9f26be7315f3dd5beae8a89777c7830a466bcc45c06011ab2b90
8afb8cfd3e73219b3fe25491ea8cbfb42b335cec425eb984b8dedc72c6d0ea7f.file
sample
    <TRUNCATED>
hda.exe.bin
updxs.exe
lin12.exe
skaj1.exe

[+] application [+]

Manual Upload
web-browsing
http-proxy
naver-mail
ftp

[+] country [+]

Korea Republic Of
United States
Australia
China
Italy
Canada
Viet Nam

[+] industry [+]

High Tech
Wholesale and Retail
Manufacturing
Higher Education
Government
Hospitality

[+] processed 1056 sessions [+]
```

The above shows a varied distribution throughout industry and country (non-targeted most likely), and some additional filenames you may want to search for.

There are also a few special ways you can take the data returned from the functions and output them for other tools. Below is creating a yara rule out of 4 sections of DA for a hash.

##### yara_rule

```
python af_lenz.py -i hash -q cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03 -o connection,dns,http,mutex -r hash_scrape -s yara_rule

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03"}]}

[+] hashes [+]

cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03

[+] connection [+]

winlsm.exe , connect , 91.185.215.141:989 , 2 , SI
winlsm.exe , connect , 193.235.147.11:80 , 2 , SE
winlsm.exe , connect , 46.36.221.85:80 , 2 , EU
smss-mon.exe , tcp-connection , 193.235.147.11:80 ,  , SE
smss-mon.exe , tcp-connection , 46.36.221.85:80 ,  , EU
smss-mon.exe , tcp-connection , 217.172.179.88:989 ,  , DE
smss-mon.exe , tcp-connection , 217.172.179.88:14450 ,  , DE
smss-mon.exe , tcp-connection , 80.78.242.47:80 ,  , RU

[+] dns [+]

iholpforyou4.com , 46.36.221.85 , A
markovqwesta.com , 193.235.147.11 , A
markovqwesta.com , ns4.cnmsn.com , NS
iholpforyou4.com , ns4.cnmsn.com , NS
iholpforyou4.com , ns3.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] http [+]

markovqwesta.com , GET , /que.php , pb
iholpforyou4.com , GET , /d_index.php , pb
80.78.242.47 , GET , /pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW ,

[+] mutex [+]

winlsm.exe , CreateMutexW , Local\!IETld!Mutex
winlsm.exe , CreateMutexW , IESQMMUTEX_0_208
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!cookies!
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!history!history.ie5!
smss-mon.exe , CreateMutexW , WininetConnectionMutex
smss-mon.exe , CreateMutexW , <NULL>

[+] processed 1 hashes with a BGM filter of 10000 [+]

[+] yara rule [+]

rule autogen_afLenz
{
	// Namespace(commonality=100, filter=10000, ident='hash', limit=200, output='connection,dns,http,mutex', query=u'cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03', run='hash_scrape', special='yara_rule')

	strings:
		$connection_0 = "91.185.215.141"
		$connection_1 = "193.235.147.11"
		$connection_2 = "46.36.221.85"
		$connection_3 = "193.235.147.11"
		$connection_4 = "46.36.221.85"
		$connection_5 = "217.172.179.88"
		$connection_6 = "217.172.179.88"
		$connection_7 = "80.78.242.47"
		$dns_0 = "iholpforyou4.com" wide ascii
		$dns_2 = "markovqwesta.com" wide ascii
		$dns_5 = "ns4.cnmsn.com" wide ascii
		$dns_9 = "ns3.cnmsn.com" wide ascii
		$http_1 = "/que.php" wide ascii
		$http_4 = "/d_index.php" wide ascii
		$http_7 = "/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW" wide ascii

	condition:
		1 of ($connection*, $http*, $dns*) /* Adjust as needed for accuracy */
}
```

You can also build an AutoFocus query based on the output.

##### af_import

```
python af_lenz.py -i hash -q cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03 -o connection,dns,http,mutex -r hash_scrape -s af_import

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03"}]}

[+] hashes [+]

cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03

[+] connection [+]

winlsm.exe , connect , 91.185.215.141:989 , 2 , SI
winlsm.exe , connect , 193.235.147.11:80 , 2 , SE
winlsm.exe , connect , 46.36.221.85:80 , 2 , EU
smss-mon.exe , tcp-connection , 193.235.147.11:80 ,  , SE
smss-mon.exe , tcp-connection , 46.36.221.85:80 ,  , EU
smss-mon.exe , tcp-connection , 217.172.179.88:989 ,  , DE
smss-mon.exe , tcp-connection , 217.172.179.88:14450 ,  , DE
smss-mon.exe , tcp-connection , 80.78.242.47:80 ,  , RU

[+] dns [+]

iholpforyou4.com , 46.36.221.85 , A
markovqwesta.com , 193.235.147.11 , A
markovqwesta.com , ns4.cnmsn.com , NS
iholpforyou4.com , ns4.cnmsn.com , NS
    <TRUNCATED>
markovqwesta.com , ns4.cnmsn.com , NS
iholpforyou4.com , ns4.cnmsn.com , NS
iholpforyou4.com , ns3.cnmsn.com , NS
markovqwesta.com , ns3.cnmsn.com , NS

[+] http [+]

markovqwesta.com , GET , /que.php , pb
iholpforyou4.com , GET , /d_index.php , pb
iholpforyou4.com , GET , /d_index.php , pb
80.78.242.47 , GET , /pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW ,
markovqwesta.com , GET , /que.php , pb

[+] mutex [+]

winlsm.exe , CreateMutexW , Local\!IETld!Mutex
winlsm.exe , CreateMutexW , IESQMMUTEX_0_208
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!cookies!
smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!history!history.ie5!
smss-mon.exe , CreateMutexW , WininetConnectionMutex
smss-mon.exe , CreateMutexW , <NULL>

[+] processed 1 hashes with a BGM filter of 10000 [+]

[+] af import query [+]

{"operator":"all","children":[{"field":"sample.tasks.connection","operator":"contains","value":"91.185.215.141:989"},{"field":"sample.tasks.connection","operator":"contains","value":"193.235.147.11:80"},{"field":"sample.tasks.connection","operator":"contains","value":"46.36.221.85:80"},{"field":"sample.tasks.connection","operator":"contains","value":"193.235.147.11:80"},{"field":"sample.tasks.connection","operator":"contains","value":"46.36.221.85:80"},{"field":"sample.tasks.connection","operator":"contains","value":"217.172.179.88:989"},{"field":"sample.tasks.connection","operator":"contains","value":"217.172.179.88:14450"},{"field":"sample.tasks.connection","operator":"contains","value":"80.78.242.47:80"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , 46.36.221.85 , A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , 193.235.147.11 , A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , ns4.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , ns4.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , ns3.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , ns3.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , 46.36.221.85 , A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , 193.235.147.11 , A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , ns4.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , ns4.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com , ns3.cnmsn.com , NS"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com , ns3.cnmsn.com , NS"},{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com , GET , /que.php , pb"},{"field":"sample.tasks.http","operator":"contains","value":"iholpforyou4.com , GET , /d_index.php , pb"},{"field":"sample.tasks.http","operator":"contains","value":"iholpforyou4.com , GET , /d_index.php , pb"},{"field":"sample.tasks.http","operator":"contains","value":"80.78.242.47 , GET , /pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW , "},{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com , GET , /que.php , pb"},{"field":"sample.tasks.mutex","operator":"contains","value":"winlsm.exe , CreateMutexW , Local\\!IETld!Mutex"},{"field":"sample.tasks.mutex","operator":"contains","value":"winlsm.exe , CreateMutexW , IESQMMUTEX_0_208"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!cookies!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!history!history.ie5!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe , CreateMutexW , WininetConnectionMutex"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe , CreateMutexW , <NULL>"}]}
```

You can also send more complex AF queries by passing the "query" value to the *-i* flag. Below we run the "uniq_sessions" function to look at session data for all samples tagged with Locky betwen March 15th-18th that were delivered via web-browsing.

##### complex_query

```
python af_lenz.py -i query -q '{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]},{"field":"sample.create_date","operator":"is in the range","value":["2016-03-15T00:00:00","2016-03-18T23:59:59"]},{"field":"session.app","operator":"is","value":"web-browsing"}]}' -r uniq_sessions

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]},{"field":"sample.create_date","operator":"is in the range","value":["2016-03-15T00:00:00","2016-03-18T23:59:59"]},{"field":"session.app","operator":"is","value":"web-browsing"}]}

[+] filename [+]

dh32f
wqi3pd
nc4f6gf
kjshdf4dj
    <TRUNCATED>
9c09891883e4170fe92321700ef42c4f
ce31e5c123842708522c5b8330481345
a02f352bb0f1e0513a7c9cc8428f353b
sample

[+] application [+]

web-browsing

[+] country [+]

Spain
South Africa
Mexico
United States
    <TRUNCATED>
Netherlands
Austria
Colombia
Korea Republic Of

[+] industry [+]

High Tech
Utilities
Higher Education
Professional and Legal Services
    <TRUNCATED>
Hospitality
Other
Automotive
Energy

[+] processed 1851 sessions [+]
```

You're also not limited to just PE files, but can run the functions on the other analyzers used in AutoFocus.

##### apk_analyzer

```
python af_lenz.py -i query -q '{"operator":"any","children":[{"field":"sample.tasks.apk_embeded_url","operator":"contains","value":"smali/com/simplelocker"},{"field":"sample.tasks.apk_suspicious_api_call","operator":"contains","value":"smali/com/simplelocker"}]}' -r common_artifacts -c 70

{"operator":"any","children":[{"field":"sample.tasks.apk_embeded_url","operator":"contains","value":"smali/com/simplelocker"},{"field":"sample.tasks.apk_suspicious_api_call","operator":"contains","value":"smali/com/simplelocker"}]}

[+] hashes [+]

92c7a01800b9eaf29c3f3808dc1b1285a2a452c2ce87888daa9cba6dedfbbb61
304efc1f0b5b8c6c711c03a13d5d8b90755cec00cac1218a7a4a22b091ffb30b
9f05372f74ddb9949f8b260ca360335651ae8282bfa615a29cd448e01667ca06
bd69ea8206070cf4db9b10a07a85412cf6be85d84d905a6b16c0bda61bbe8b55
    <TRUNCATED>
0a56882c6ae7e211e4cf3b222d8ece2b1b744ef6abb219167a834c3569e7cca8
88881454cee58f8ecbf33a5e0875ba03ceb8e3ca2660421fb986b1bb67cedd87
a71073af1c81263e90d5ec0e6ac8b3f9480ebcb0c42bc8f49be5e6c99c069bc5
2db3f60e5b8f60bc28404e2550103c9a6fb9b8f7cb5803017ad8a5cf37f1d1f8

[+] apk_misc [+]

com.simplelocker.DeviceAdminChecker
com.simplelocker.Main

[+] apk_filter [+]

android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE

[+] apk_receiver [+]

com.simplelocker.MessageReceiver
com.simplelocker.SDCardServiceStarter
com.simplelocker.MyDeviceAdminReceiver
com.simplelocker.ServiceStarter

[+] apk_service [+]

com.simplelocker.CheckService
com.simplelocker.MainService
com.simplelocker.DecryptService

[+] processed 24 hashes with a BGM filter of 10000 [+]
```

Additionally, you can also limit the number of samples to analyze - running the above query again but limiting to 5 results.

##### limit_result

```
python af_lenz.py -i query -q '{"operator":"any","children":[{"field":"sample.tasks.apk_embeded_url","operator":"contains","value":"smali/com/simplelocker"},{"field":"sample.tasks.apk_suspicious_api_call","operator":"contains","value":"smali/com/simplelocker"}]}' -r common_artifacts -c 70 -l 5

{"operator":"any","children":[{"field":"sample.tasks.apk_embeded_url","operator":"contains","value":"smali/com/simplelocker"},{"field":"sample.tasks.apk_suspicious_api_call","operator":"contains","value":"smali/com/simplelocker"}]}

[+] hashes [+]

5e650b16b6565d66d3c4ae0800b89cc4942d57d6324b2bfa41b3a331cbdc2659
c9335985a3f04611c155528827b38447f549307997715a015acc73a396d7c2b7
88881454cee58f8ecbf33a5e0875ba03ceb8e3ca2660421fb986b1bb67cedd87
a71073af1c81263e90d5ec0e6ac8b3f9480ebcb0c42bc8f49be5e6c99c069bc5
304efc1f0b5b8c6c711c03a13d5d8b90755cec00cac1218a7a4a22b091ffb30b

[+] connection [+]

unknown , tcp , 89.144.14.29:80 , DE

[+] apk_misc [+]

com.simplelocker.DeviceAdminChecker
com.simplelocker.Main

[+] apk_filter [+]

android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE

[+] apk_receiver [+]

com.simplelocker.ServiceStarter
com.simplelocker.SDCardServiceStarter
com.simplelocker.MyDeviceAdminReceiver
com.simplelocker.MessageReceiver

[+] apk_service [+]

com.simplelocker.MainService
com.simplelocker.CheckService
com.simplelocker.DecryptService

[+] processed 5 hashes with a BGM filter of 10000 [+]
```

The next function is more for quick meta-data analysis, but "sample_info" will return the hash, file type, create date, verdict, file size, and tags that associate to samples from a query. These are pipe delimeted for quick parsing.

##### meta_data

```
python af_lenz.py -i file -q "VAULT.KEY" -r meta_scrape -l 10

{"operator":"all","children":[{"field":"sample.tasks.file","operator":"contains","value":"VAULT.KEY"}]}

[+] sample_meta [+]

97e0dd5032bd0dc4877ed62ba01135644f867029aa23de71cec0eb8cd91a3ad1 | PE | 2016-09-09 09:24:02 | malware | 220992 | Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
ab2773c8ca1de56de2c2cb15801a6de57217194a4443d3538bd7bb3434e9f380 | PE | 2016-09-16 00:36:32 | malware | 204800 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ProcessHollowing,Unit42.ModifyBootConfig,Commodity.Pony
da3ebf8fd9f992e8edce27bdbe370e77e7c2981028762696058c6d4db8a5439d | PE | 2016-09-09 09:24:01 | malware | 180224 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Unit42.ProcessHollowing,Commodity.Pony
52aeb37b72aae57c23f5e007af56c32ee26ae814a2507440c6c805c948643fcc | PE | 2016-09-12 23:54:57 | malware | 224150 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
28208e03c4a1d9bb71bc4fc97fe78c7eeee11bc74be18bbb69d6f13b6f74ea20 | PE | 2016-09-13 00:18:07 | malware | 222921 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
58c834338eee25fc44f1c4178feb446c1a1dd433094d4bad211d6d255de25993 | PE | 2016-09-14 01:04:36 | malware | 122918 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ProcessHollowing,Unit42.ModifyBootConfig,Commodity.Pony
395eec01a2a71c36d461c2e84b3707b3c03375bfbea3618bc50c540fd5323884 | PE | 2016-09-15 09:23:41 | malware | 224152 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
0c7167d0ea4a6e997f92d43ecdbbb8063f12f906b0fcb71801182df18629d2ea | PE | 2016-09-12 09:39:34 | malware | 220638 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
330877e342fe05bc7c6260315c1e812d19242bf523df1c6528fe7148f42ca991 | PE | 2016-09-13 00:13:02 | malware | 221492 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony
13f2864d4ab5cdc900f6cca9d031bdc2cfa91b764920b722d60d54462e61d4da | PE | 2016-09-15 17:30:15 | malware | 222921 | Unit42.RansomCrypt,Unit42.DeleteVolumeSnapshots,Unit42.ModifyBootConfig,Commodity.Pony

[+] processed 10 samples [+]
```

##### extract_all

You can also use the "hash_scrape" function to pull back ALL data across a set of samples or leverage the "common_artifacts" function, with a commonality of 0% (meaning everything is a match), to take advantage of outputs like "range". For example, if you want to know every unique Process entry across a sample set for further analysis and know how common each one is.

```
python af_lenz.py -i dns -q markovqwesta.com -r common_artifacts -c 0 -o process -s range

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

639d03fb6465a94189fb5b29887afe0965a95c9a7778fb624b92eef6ed22b7bb
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
    <TRUNCATED>
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099
ffe9fb1f9ef7465c99edfe17ccce496172cba47357b2caff6720900a0f6426b2
c97bd3d159222bfe650647aefb92fd13b2e590f8d5dd5781110a0cf61958fc33

[+] process [+]

16  | ntsystem.exe , LoadLibraryExW , hnetcfg.dll ,  , 0
8   | mswinlogon.exe , LoadLibraryExW , USER32.dll ,  , 0
8   | ntreader_sl.exe , LoadLibraryExW , ADVAPI32.dll ,  , 0
8   | wincsrss.exe , ZwTerminateProcess , ntwinlogon.exe ,
    <TRUNCATED>
8   | wincsrss.exe , LoadLibraryExW , Windows\SysWOW64\ieframe.dll ,  , 8
8   | winlogonsvc.exe , LoadLibraryExW , WININET.dll ,  , 0
8   | ntcsrss.exe , GetModuleHandle , documents and settings\administrator\sample.exe
8   | system-updater.exe , LoadLibraryExW , SHELL32.dll ,  , 0

[+] processed 12 hashes with a BGM filter of 10000 [+]
```

##### quiet_flag

The 'Q' flag can be used in combination with any other valid set of arguments to limit the output of the script.  When invoked, this flag suppresses any informational output that is normally generated by the script.  As a result, the only output returned by the script is returned data.  This can then be manipulated easily with other tools.

```
python af_lenz.py -i dns -q 'www.otrfmbluvrde.com' -r meta_scrape -o sha256,file_size,file_type -Q

04b770027efe3259f6ed6bba5e91fd3309ab44f74f4022efc3321576fc969da0 | 11208 | Adobe Flash File
7ddb1610dc730cbd76786d834236a24b3b5f51fe5d14755b65b7ff8531b6806f | 11208 | Adobe Flash File
4dfb5da4aa0e5e58d811392ea902a40d4cdecc9f1a267656d5564c341226488f | 11208 | Adobe Flash File
80d04c67ec1699b370ddd8d9a6dacab51fa5ebcefbfb992b329cef404827da5e | 11208 | Adobe Flash File
5562ac2ef1fa431ac34cd4c332fc269c3fbca789a8417ee6f27d5433f88a0bbd | 11208 | Adobe Flash File
ad9264b8e777ad84343633d0b972b6fecef9a7e46a151caf84019ef49ff64427 | 4304  | Adobe Flash File
```

##### diff

The 'diff' function allows you to compare two hashes and identify the differences between each one. It will not print common-lines.

```
python af_lenz.py -i dns -q 'www.otrfmbluvrde.com' -r diff -o process,mutex,dns

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"www.otrfmbluvrde.com"}]}

[+] hashes [+]

04b770027efe3259f6ed6bba5e91fd3309ab44f74f4022efc3321576fc969da0
7ddb1610dc730cbd76786d834236a24b3b5f51fe5d14755b65b7ff8531b6806f

[+] diff [+]

< | 04b770027efe3259f6ed6bba5e91fd3309ab44f74f4022efc3321576fc969da0
> | 7ddb1610dc730cbd76786d834236a24b3b5f51fe5d14755b65b7ff8531b6806f

[+] process [+]

< | svchost.exe , created ,  , Windows\System32\taskeng.exe , taskeng.exe {F03FAC4A-6277-42B8-8C74-F5AA3E77F347} S-1-5-18:NT AUTHORITY\System:Service:
< | iexplore.exe , SetTimer , 00000001 , 00001388(original:00001388) , 726D4756
< | iexplore.exe , SetTimer , 00007feb , 00001388(original:00001388) , 726D4756
< | iexplore.exe , SetTimer , 00000000 , 00001388(original:000088b8) , 73586B52
---
> | svchost.exe , created ,  , Windows\System32\taskeng.exe , taskeng.exe {CD585D04-948B-4287-9C53-FC33C8D8F4D7} S-1-5-18:NT AUTHORITY\System:Service:
> | iexplore.exe , SetTimer , 00000001 , 00001388(original:00001388) , 72AD4756
> | iexplore.exe , SetTimer , 00007feb , 00001388(original:00001388) , 72AD4756
> | iexplore.exe , SetTimer , 00000000 , 00001388(original:000088b8) , 73B06B52

[+] mutex [+]

< | iexplore.exe , CreateMutexW , Groove:PathMutex:wEfok5Qw0IjiXFzS91XPfTjqjes=
< | iexplore.exe , CreateMutexW , Groove:PathMutex:gWNhnwLaz/1PBZUWP+4N4Zd81LY=
---
> | iexplore.exe , CreateMutexW , Groove:PathMutex:MFJQHMsconMFS29BQOwAYulej6k=
> | iexplore.exe , CreateMutexW , Groove:PathMutex:5/aBAYZWYsoJ3j53zcvNAGvCHSo=

[+] dns [+]

< | wpad.XKTMLKA99660986.local ,  , NXDOMAIN
---
> | wpad.ZPCTGVR49286334.local ,  , NXDOMAIN

[+] processed 2 hashes with a BGM filter of 10000 [+]
```

##### count

The 'count' parameter can be passed to the 'special' function and will count the number of unique lines per hash across the sample set. This allows you to see how frequently something occurred.

```
python af_lenz.py -i dns -q 'markovqwesta.com' -r hash_scrape -o dns -s count -l 15

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

639d03fb6465a94189fb5b29887afe0965a95c9a7778fb624b92eef6ed22b7bb
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
    <TRUNCATED>
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099
ffe9fb1f9ef7465c99edfe17ccce496172cba47357b2caff6720900a0f6426b2
c97bd3d159222bfe650647aefb92fd13b2e590f8d5dd5781110a0cf61958fc33

[+] dns [+]

9    | markovqwesta.com , 193.235.147.11 , A
1    | iholpforyou4.com ,  , NXDOMAIN
10   | markovqwesta.com , ns4.cnmsn.com , NS
10   | markovqwesta.com , ns3.cnmsn.com , NS
1    | iholpforyou4.com , 46.36.221.85 , A
1    | iholpforyou4.com , ns4.cnmsn.com , NS
1    | iholpforyou4.com , ns3.cnmsn.com , NS
2    | exseomonstars.com ,  , NXDOMAIN
2    | markovqwesta.com ,  , NXDOMAIN
1    | markovqwesta.com , 176.114.3.49 , A
1    | support.microsoft.com , 157.56.56.139 , A
1    | www.mozilla.com , 63.245.217.20 , A

[+] processed 12 hashes with a BGM filter of 10000 [+]
```

##### tag_count

The 'tag_count' parameter can be passed to the special function to count the raw number of tags per sample. This allows you to quickly take a large set of samples and boil up tags with large coverage.

```
python af_lenz.py -i tag -q 'Unit42.AlphaCrypt' -r meta_scrape -s tag_count

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.AlphaCrypt"]}]}

[+] sample_meta [+]

   72 | Unit42.IPAddressLookup
    1 | Unit42.ModifyWindowsFirewall
   72 | Unit42.TeslaCrypt
    1 | Commodity.Virut
   60 | Unit42.ProcessHollowing
   72 | Unit42.AlphaCrypt
   72 | Unit42.DeleteVolumeSnapshots

[+] processed 72 samples [+]
```

##### suspect_artifacts

The 'suspicious' and 'highly_suspicious' parameters can be passed to the filter function to use the AutoFocus definitions to filter artifacts. These are presented in AF as red and yellow exclamation points.

```
$ python af_lenz.py -i tag -q 'Unit42.AlphaCrypt' -r hash_scrape -l 1 -f highly_suspicious -o dns,mutex

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.AlphaCrypt"]}]}

[+] hashes [+]

0ca8a7f1c443af649230f95ab18638e0e1238d74d6ab0efe0d14b883ae7bd592

[+] dns [+]

wpad.ZPAN28185489917.local ,  , NXDOMAIN
dpckd2ftmf7lelsa.tor2web.blutmagie.de.FYRNF5563656069.local ,  , NXDOMAIN
dpckd2ftmf7lelsa.9isernvur33.com.FYRNF5563656069.local ,  , NXDOMAIN
dpckd2ftmf7lelsa.9isernvur33.com ,  , NXDOMAIN
dpckd2ftmf7lelsa.afnwdsy4j32.com.FYRNF5563656069.local ,  , NXDOMAIN
dpckd2ftmf7lelsa.afnwdsy4j32.com ,  , NXDOMAIN
dpckd2ftmf7lelsa.tor2web.org , 38.229.70.4 , A
dpckd2ftmf7lelsa.tor2web.blutmagie.de ,  , NXDOMAIN

[+] mutex [+]

gdgvaux.exe , CreateMutexW , VideoRenderer
gdgvaux.exe , CreateMutexW , <NULL>
gdgvaux.exe , CreateMutexW , safsdfasdfwrtqr15
gdgvaux.exe , CreateMutexW , c:!docume~1!admini~1!locals~1!temp!temporary internet files!content.ie5!
gdgvaux.exe , CreateMutexW , c:!docume~1!admini~1!locals~1!temp!cookies!
gdgvaux.exe , CreateMutexW , c:!docume~1!admini~1!locals~1!temp!history!history.ie5!

[+] processed 1 hashes with a BGM filter of highly_suspicious [+]
```

The same hash with a different filter, resulting in different data.

```
$ python af_lenz.py -i tag -q 'Unit42.AlphaCrypt' -r hash_scrape -l 1 -f suspicious -o dns,mutex

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.AlphaCrypt"]}]}

[+] hashes [+]

0ca8a7f1c443af649230f95ab18638e0e1238d74d6ab0efe0d14b883ae7bd592

[+] dns [+]

tor2web.org , ns1.dnsimple.com , NS
ilo.brenz.pl , 148.81.111.121 , A
ipinfo.io , ns-595.awsdns-10.net , NS

[+] mutex [+]

winlogon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
winlogon.exe , CreateMutexW , c:!documents and settings!administrator!cookies!
winlogon.exe , CreateMutexW , c:!documents and settings!administrator!local settings!history!history.ie5!
winlogon.exe , CreateMutexW , WininetConnectionMutex
winlogon.exe , CreateMutexW , <NULL>
sample.exe , CreateMutexW , VideoRenderer
winlogon.exe , CreateMutexW , Global\WindowsUpdateTracingMutex

[+] processed 1 hashes with a BGM filter of suspicious [+]
```

##### service_scrape

Scrape the unique service names out of a set of samples.

```
$ python af_lenz.py -i query -q '{"operator":"all","children":[{"field":"sample.tasks.service","operator":"has any value","value":""},{"field":"sample.malware","operator":"is","value":1},{"field":"sample.tasks.dns","operator":"has any value","value":""}]}' -r service_scrape -l 10

{"operator":"all","children":[{"field":"sample.tasks.service","operator":"has any value","value":""},{"field":"sample.malware","operator":"is","value":1},{"field":"sample.tasks.dns","operator":"has any value","value":""}]}

[+] hashes [+]

e902f59fedc8b13e87baa33c7ad7a13401653b7340c2501e4a314048333b5215
51c62ee5e38f111928b45585d7c70ba91f973b664fa74d390661b5007130758d
4859a2938f3af469274f6b98747f7cbff579eeea754b88d481e7c1a44c320136
dd7f0b9edadbbda92ab73430536d1d36e8641170a664767fe2316fd7454f6a5e
    <TRUNCATED>
ef9e299d56d9ce67d5c4b472d52310cc3a28c3aaf169c60a02c97dd96bd3d323
66bc9c714e69c54f8757dab13c2924d5257141ae77867d127ba5053ba5f283ef
5cbea737b5f88e16bbc96952eb1310a3fa0c51f25a81a5212f5b01ebe6c4eb5f
5fa6d5012d2df74a22536f8a7a4c240bb36464873ff62b4dcaed8bedea2bcb2e

[+] service [+]

SysCPRC
QMgcIwoT

[+] processed 10 hashes with a BGM filter of 10000 [+]
```

##### write_out

The "-w" flag can be used to specify that STDOUT be redirected to a file.

```
$ python af_lenz.py -i query -q '{"operator":"all","children":[{"field":"sample.tasks.service","operator":"has any value","value":""},{"field":"sample.malware","operator":"is","value":1},{"field":"sample.tasks.dns","operator":"has any value","value":""}]}' -r service_scrape -l 10 -w aflenz.txt -Q

$ cat aflenz.txt
SysCPRC
QMgcIwoT
```

##### bgm_value

The "bgm" parameter can be passed to the "-s" flag to print the B(enign), G(rayware), and M(alware) counts for each associated artifact.

```
$ python af_lenz.py -i dns -q "markovqwesta.com" -l 1 -r hash_scrape -s bgm -f 0 -o process

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

8ef7212841ca0894232c2d118905dfacdcad16d00ca545745eff7123565b5b39

[+] process [+]

19.7K 9.9M  82.1K | svchost.exe , created ,  , Users\Administrator\sample.exe ,  Users\Administrator\sample.exe
0     0     1     | sample.exe , created ,  , Users\Administrator\AppData\Local\FWJ\csrss_patcher.exe ,  Users\sciZnBNl6e0Mg\AppData\Local\FWJ\csrss_patcher.exe
15.0K 6.0M  65.0K | svchost.exe , terminated ,  , Users\Administrator\sample.exe
0     0     1     | csrss_patcher.exe , created ,  , Users\Administrator\AppData\Local\FWJ\syswinlogon.exe ,  Users\sciZnBNl6e0Mg\AppData\Local\FWJ\syswinlogon.exe
0     0     1     | csrss_patcher.exe , created ,  , Windows\SysWOW64\netsh.exe ,  Windows\System32\netsh.exe  firewall add allowedprogram  Users\sciZnBNl6e0Mg\AppData\Local\FWJ\csrss_patcher.exe   Windows Microsoft .NET Framework NGEN v4.0.30319_X64  ENABLE
337M  9.6M  79.5K | csrss.exe , created ,  , Windows\System32\conhost.exe , \??\Windows\system32\conhost.exe
0     0     1     | csrss_patcher.exe , terminated ,  , Windows\SysWOW64\netsh.exe
370M  7.9M  87.6K | winlogon.exe , terminated ,  , Windows\System32\userinit.exe
85.3K 764K  15.7K | svchost.exe , terminated ,  , Windows\System32\mobsync.exe
354M  10.4K 87.6K | unknown , terminated ,  , Program Files (x86)\Adobe\Reader 11.0\Reader\reader_sl.exe
376M  11.6K 92.8K | SearchIndexer.exe , terminated ,  , Windows\System32\SearchProtocolHost.exe
376M  11.6K 92.9K | cmd.exe , terminated ,  , Users\Administrator\explorer.exe
393M  11.7K 93.4K | explorer.exe , terminated ,  , WINDOWS\system32\cmd.exe
```

##### tag_info

Returns the basic tag meta-data.

```
$ python af_lenz.py -i tag -q 'Commodity.NJRat' -r tag_info

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Commodity.NJRat"]}]}

[+] Tag Info [+]

Tag Name        : NJRat
Tag Public Name : Commodity.NJRat
Tag Count       : 815787
Tag Created     : 2016-01-01 00:00:00
Tag Last Hit    : 2017-02-22 07:55:00
Tag Class       : malware_family
Tag Status      : enabled
Tag Description : NJRat is a remote-access Trojan that has been used for the last few years. We haven’t heard much about NJRat since April 2014, but some samples we’ve recently received show that this malware is making a comeback. ( For some background on NJRat,  a 2013 report from Fidelis Cybersecurity Solutions at General Dynamics detailed indicators, domains, and TTP’s in conjunction with cyber-attacks using NJRat.)
```

##### tag_check

```
$ python af_lenz.py -i tag -q 'Commodity.NJRat,2ea576290117ca82cb55f599e00233eb963d940f96ed05f5ce31e7262573e212' -r tag_check

Tag:   Commodity.NJRat
Hash:  2ea576290117ca82cb55f599e00233eb963d940f96ed05f5ce31e7262573e212

[+] Matched Query [+]

{u'operator': u'contains', u'field': u'sample.tasks.registry', u'value': u'SetValueKey , HKCU\\Environment\\SEE_MASK_NOZONECHECKS , Value:1 , Type:1'}

[+] registry [+]

sample.exe , SetValueKey , HKCU\Environment\SEE_MASK_NOZONECHECKS , Value:1 , Type:1

[+] Matched Query [+]

{u'operator': u'contains', u'field': u'sample.tasks.registry', u'value': u'HKCU\\Environment , SEE_MASK_NOZONECHECKS , 1'}

[+] registry [+]

sample.exe , RegSetValueEx , HKCU\Environment , SEE_MASK_NOZONECHECKS , 1

[+] processed 1 hashes with a BGM filter of 0 [+]
```

### [+] CHANGE LOG [+]

v1.2.1 - 05APR2017
* Changed internal hash_lookup section to only pull the requested sections as opposed to all - should save bandwidth and speed things up for queries with thousands of requests.

v1.2.0 - 22FEB2017
* Fixed an issue with 'count' function processing more than the expected sections.
* Added the following new APK sections: apk_app_icon, apk_cert_file, apk_defined_activity, apk_defined_intent_filter, apk_digital_signer, apk_embedded_library, apk_isrepackaged, apk_name, apk_packagename, apk_suspicious_action_monitored, apk_suspicious_file, apk_suspicious_pattern, apk_version_num.
* Added the following new MAC sections: mac_embedded_file, mac_embedded_url.
* Added the following new Session sections: device_country_code, device_country, device_hostname, business_line, device_model, device_serial, device_version, dst_country_code, dst_ip, dst_port, email_charset, src_country_code, src_country, src_ip, src_port, timestamp.
* Renamed the following sections to align with client library: apk_receiver => apk_defined_receiver, apk_sensor => apk_defined_sensor, apk_service => apk_defined_service, apk_embedurl => apk_embeded_url, apk_file => apk_internal_file, apk_permission => apk_requested_permission, apk_sensitiveapi => apk_sensitive_api_call, apk_suspiciousapi => apk_suspisicous_api_call, apk_string => apk_suspicious_string, behavior_desc => behavior.
* Added new "bgm" parameter to "-s" flag which will print the B(enign), G(rayware), and M(alware) counts per artifact.
* Added "tag_info" function which returns the tag meta-data.
* Added "tag_check" function, which should be considered BEST EFFORT. It will take each defined query for a tag and attempt to identify which sub-queries caused the sample to be tagged. Supports "contains", "is", "in the list", "regexp", and "proximity" but highly complex rules may cause problems.

v1.1.9 - 21DEC2016
* Added "service_scrape" function to extract unique service names from a set of samples.
* Added "-w" flag so that STDOUT can be redirected to a file.
* Centralized all print operations into a new function and enabled utf-8 encoding. This should address problems with encoding errors that pop up infrequently with session data.
* Passing "0" to the "filter" or "limit" function will now cause it to default to 1 billion, thus practically negating filtering or session/sample limits.

v1.1.8 - 15NOV2016
* Added "input_file_query" as input so Windows users can directly load queries from a file and avoid quote escaping from CLI.
* Added "suspicious" and "highly_suspicious" options to "filter" function that use pre-defined filtering templates for malware artifacts. More information can be found in the AF documentation: https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/get-started-with-autofocus/autofocus-concepts
* Suspicious artifacts have been widely-detected across large numbers of samples. Are most frequently detected with malware. Although suspicious artifacts can be detected with grayware and benign samples, they are more often found with malware.
* The "suspicious" filter displays artifacts with a malware count 3 times larger than benign with a total malware count greater than 500. 
* Highly Suspicious artifacts have been detected in very few samples. The lack of distribution of these types of artifacts could indicate an attack crafted to target a specific organization. Are most frequently detected with malware. In some cases, these artifacts have been exclusively seen with malware and never with grayware or benign samples.
* The "highly_suspicious" filter displays artifacts with a malware count 3 times larger than benign but has a total malware less than 500.
* Added "tag_count" value to special parameter. This will count each individual tag across a set of samples.

v1.1.7 - 11OCT2016
* Added "diff" function to identify differences between two samples.
* Added "count" value to special parameter. This works on hash_scrape/uniq_sessions functions and returns count of each line across sample sets.
* Added Java API ("japi") and Behavior Description ("behavior_desc") sections.
* Cleaned up code to make adding new sections straight-forward (1 location vs multiple) and fixed logic issue for "behavior_type" section.
* Modified print functions to use auto-adjusting columns.

v1.1.6 - 16SEP2016
* Added auto-adjusting columns for meta and session scraped output.
* Added "timestamp" to session output modifiers.

v1.1.5 - 01AUG2016
* Added support for reading SHA256 hashes from a flat file.

v1.1.4 - 28JUL2016
* Added support for a quiet flag.  This flag suppresses the extra output of the script so as to make the returned data easier to process with other utilities.

v1.1.3 - 20JUL2016
* Flushed out the session scrape outputs to now include src_country, dst_country, src_ip, dst_ip, src_port, dst_port.

v1.1.2 - 13JUL2016
* Added new function, "session_scrape", which acts similar to meta_scrape except for session data.

v1.1.1 - 12JUL2016
* Switched from threading to multiprocessing to improve speed.
* Switched from using passed arguments directly to allow for more flexibility in future updates.

v1.1.0 - 08JUN2016
* Added ability to specify meta_scrape sections "sha256", "sha1", "md5" "file_type", "create_date", "verdict", "file_size", "tags", "ssdeep", "imphash", and "digital_signer". 
* Added "imphash" and "digital_signer" to existing section lists for all sample functions.

v1.0.9 - 18MAY2016
* Switched from "scan" to "search" for non-research enabled API keys. Add "[researcher] enabled=True" to your client library configuration file, or environment variable, to enable scan.
* Added company to session output as an option.

v1.0.8 - 27APR2016
* Changed "hash_lookup" to "hash_scrape" and created a new function around it to support multiple hashes instead of one.
* Added query output to Yara rule generation.
* Cleaned up code for final release to public.
* Initial public release of AutoFocus Lenz.

v1.0.7 - 21APR2016
* Fixed scrape functions not being parsed correctly for Yara rule generation.

v1.0.6 - 18APR2016
* Added output "range" to print commonality match percents next to artifacts.

v1.0.5 - 06APR2016
* Added function "sample_meta" to return meta data about identified samples.

v1.0.4 - 04APR2016
* Added *-l* flag to limit the number of samples for analysis.
* Added APK sample sections for output.
* Fixed a number of logic issues.
* Cleaned up code significantly.

v1.0.3 - 31MAR2016
* Moved to BitBucket.
* Merged updates into code.

v1.0.2 - 22MAR2016
* Converted over to using _raw_line for everything.

v1.0.1 - 19MAR2016
* Added "query" identifier so you can pass AF queries directly on CLI.
* Added escaping to file/registry supplied queries.

v1.0.0 - 17MAR2016
* Initial release of af_lenz.py.

### [+] FUTURE TO-DOs [+]

In no particular order...
* None

### [+] NOTES [+]

If you find any issues or have requests for functionality, please contact Jeff White.