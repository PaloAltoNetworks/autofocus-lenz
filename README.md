## af_lenz

### [+] INTRO [+]

The AutoFocus API exposes a wealth of dynamic analysis information about malware activities from disk to wire, which is made easily accessible for scripting through the [AutoFocus Python Client Library](https://github.com/PaloAltoNetworks/autofocus-client-library). The goal of *af_lenz.py* is to build ontop of the client library by providing a set of helpful tools to aide incident responders, or analysts, in rapidly extracting information from AutoFocus that can be used for operational intelligence.

```
python af_lenz.py -h
usage: af_lenz.py [-h] -i <query_type> -q <query> [-o <section_output>]
                  [-f <number>] [-l <number>] -r <function_name>
                  [-s <special_output>] [-c <integer_percent>]

Run functions to retrieve information from AutoFocus.

optional arguments:
  -h, --help            show this help message and exit
  -i <query_type>, --ident <query_type>
                        Query identifier type for AutoFocus search. [hash,
                        hash_list, ip, network, dns, file, http, mutex,
                        process, registry, service, user_agent, tag, query]
  -q <query>, --query <query>
                        Value to query Autofocus for.
  -o <section_output>, --output <section_output>
                        Section of data to return. Multiple values are comma
                        separated (no space) or "all" for everything, which is
                        default. [email_subject, filename, application,
                        country, industry, email_sender, fileurl,
                        email_recipient, service, registry, process, misc,
                        user_agent, mutex, http, dns, behavior_type,
                        connection, file, apk_misc, apk_filter, apk_receiver,
                        apk_sensor, apk_service, apk_embedurl, apk_permission,
                        apk_sensitiveapi, apk_suspiciousapi, apk_file,
                        apk_string]
  -f <number>, --filter <number>
                        Filter out Benign/Grayware/Malware counts over this
                        number, default 10,000.
  -l <number>, --limit <number>
                        Limit the number of analyzed samples, default 200.
  -r <function_name>, --run <function_name>
                        Function to run. [uniq_sessions, common_artifacts,
                        common_pieces, hash_scrape, http_scrape, dns_scrape,
                        mutex_scrape, meta_scrape]
  -s <special_output>, --special <special_output>
                        Output data formated in a special way for other tools.
                        [yara_rule, af_import, range]
  -c <integer_percent>, --commonality <integer_percent>
                        Commonality percentage for comparison functions,
                        default is 100
```

Quick links to examples (not working in BitBucket...):
* [Hash Scrape function](#markdown-header-hash_scrape)
* [Common Artifacts function](#markdown-header-common_artifacts)
* [Common Pieces function](#markdown-header-common_pieces)
* [Show commonality range](#markdown-header-range)
* [HTTP Scrape function](#markdown-header-http_scrape)
* [DNS Scrape function](#markdown-header-dns_scrape)
* [Mutex Scrape function](#markdown-header-mutex_scrape)
* [Unique Sessions function](#markdown-header-uniq_sessions)
* [Generate Yara rule](#markdown-header-yara_rule)
* [Generate AutoFocus query](#markdown-header-af_import)
* [Control output](#markdown-header-section_output)
* [Set commonality percent](#markdown-header-commonality)
* [Submit complex AutoFocus queries](#markdown-header-complex_query)
* [Analyze non-PE files](#markdown-header-apk_analyzer)
* [Limit analyzed samples](#markdown-header-limit_result)
* [Collect bulk sample meta data](#markdown-header-meta_data)
* [Extract all unique entries](#markdown-header-extract_all)

### [+] CHANGE LOG [+]

v1.0.8 - 27APR2016
* Changed "hash_lookup" to "hash_scrape" and created a new function around it to support multiple hashes instead of one.
* Added query output to Yara rule generation.
* Cleaned up code for final release to public.

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

[+] user_agent [+]

pb

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

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
c19487136ebc82a38e13264ca8bd1b7983039db103d2520c52e49f40ac35b1db
c550a0730c9cf10751a3236ef57fafb5af844bef3874855a215519a9ffcec348
    <TRUNCATED>
234203c3e40184c430331c266b4108db94b3f68258410b7592da81d6abc88b7d
1963a881beefd720648ca9a28c578b4f10f6ea38a8dfab436756fd64dc418bc3
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099

[+] registry [+]

33 |sample.exe , SetValueKey , HKCU\Software\kg\cat ,
33 |sample.exe , DeleteValueKey , HKCU\Software\kg\chk ,
33 |sample.exe , DeleteValueKey , HKCU\Software\kg\main ,
33 |sample.exe , SetValueKey , HKCU\Software\kg\chk ,
    <TRUNCATED>
33 |sample.exe , DeleteValueKey , HKCU\Software\kg\main
33 |sample.exe , RegCreateKeyEx , HKCU , SOFTWARE\kg
33 |sample.exe , DeleteValueKey , HKCU\Software\kg\name
33 |sample.exe , DeleteValueKey , HKCU\Software\kg\chk

[+] user_agent [+]

75 |pb

[+] mutex [+]

33 |sample.exe , CreateMutexW , PB_SN_MUTEX_GL_F348B3A2387

[+] http [+]

75 |markovqwesta.com , GET , /que.php , pb

[+] dns [+]

75 |markovqwesta.com , 193.235.147.11 , A
83 |markovqwesta.com , ns4.cnmsn.com , NS
83 |markovqwesta.com , ns3.cnmsn.com , NS

[+] connection [+]

66 |unknown , tcp , 193.235.147.11:80 , SE

[+] file [+]

33 |unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[2].htm
33 |sample.exe , Write , Windows\SysWOW64\9125y5yta.dat
33 |netsh.exe , CreateFileFail , Users\Administrator\sample.exe , 00000080 , 00200000 , c0000034
33 |unknown , create , C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[1].htm , md5=46788efce76ebf3e09fc844af99c5309 , sha1=d25ec96232263c0eb834d9c7b437dbe97029a809 , sha256=3376bb271f1e1e7b2e0eb28475f8bab01ed69627861682ac809a732cb023d230
33 |sample.exe , Write , WINDOWS\system32\9125y5yta.dat ,

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

8633e5fafb733bcfdaf6e8d236c6ef6c9352afd4708dd6b239e28dbf76581437 | PE         | 2016-04-03 21:00:49 | malware    | 172032     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots', u'Commodity.Pony']
99d6e828adcda3207b5ee7f2850fbb6c9e73c0c3e4d302bb94094acaf1a973f3 | PE         | 2016-03-15 21:00:25 | malware    | 151552     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots', u'1504.TorHiddenService', u'Commodity.Pony']
dd34c090ddac627ed38df222df013f720be2480e65e5ac7f134f45569c267522 | PE         | 2016-03-14 22:37:01 | malware    | 200704     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots', u'1504.TorHiddenService', u'Commodity.Pony']
5769d7a68cea66a0972ce657ecca8006bbbb68b15254fce2f721ef7705f86110 | PE         | 2016-03-14 10:58:29 | malware    | 187289     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots']
678dda0327f46c03912693b8092b068b6ee59a8503fd2be322be92735aa469a7 | PE         | 2016-02-23 18:57:28 | malware    | 79965      | [u'Unit42.RansomCrypt', u'1504.Delete_VolumeSnapshots']
f2a1abba968355c1e4a37e9a3cb4ff91a080f8720bdafc533d6023e26dfa120c | PE         | 2016-02-21 09:23:23 | malware    | 110807     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots']
a996ce853783a92927856b8559e157c20c7a950b68da4bc214568d32e9246352 | PE         | 2016-02-18 17:05:04 | malware    | 186882     | [u'Unit42.RansomCrypt', u'1504.BCDEdit', u'1504.Delete_VolumeSnapshots']
b20d67bab9c75b02c5894299f332fff9d34ace41e1a9042f39f1799d0f457df6 | PE         | 2016-01-29 18:15:49 | malware    | 112642     | [u'Unit42.RansomCrypt']
69d023ca57f4e3fdf7280ca4e5a5a7b547797f467315eaf462d6cf3cbf8696cc | PE         | 2016-01-22 19:42:54 | malware    | 135682     | [u'Unit42.RansomCrypt']
dae88a5dac46e9e15a1ed71be06613c1d6f98d532063e13414f4fb8795c87de8 | PE         | 2016-01-27 17:13:32 | malware    | 168450     | [u'Unit42.RansomCrypt']

[+] processed 10 samples [+]
```

##### extract_all

You can also use the "hash_scrape" function to pull back ALL data across a set of samples or leverage the "common_artifacts" function, with a commonality of 0% (meaning everything is a match), to take advantage of outputs like "range". For example, if you want to know every unique Process entry across a sample set for further analysis and know how common each one is.

```
python af_lenz.py -i dns -q markovqwesta.com -r common_artifacts -c 0 -o process -s range

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"markovqwesta.com"}]}

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

[+] process [+]

16 |ntsystem.exe , LoadLibraryExW , hnetcfg.dll ,  , 0
8 |mswinlogon.exe , LoadLibraryExW , USER32.dll ,  , 0
8 |ntreader_sl.exe , LoadLibraryExW , ADVAPI32.dll ,  , 0
8 |wincsrss.exe , ZwTerminateProcess , ntwinlogon.exe ,
    <TRUNCATED>
8 |wincsrss.exe , LoadLibraryExW , Windows\SysWOW64\ieframe.dll ,  , 8
8 |winlogonsvc.exe , LoadLibraryExW , WININET.dll ,  , 0
8 |ntcsrss.exe , GetModuleHandle , documents and settings\administrator\sample.exe
8 |system-updater.exe , LoadLibraryExW , SHELL32.dll ,  , 0

[+] processed 12 hashes with a BGM filter of 10000 [+]
```
