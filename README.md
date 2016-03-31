## af_lenz

### [+] INTRO [+]

The AutoFocus API exposes a wealth of dynamic analysis information about malware activities from disk to wire, which is made easily accessible for scripting through the [AutoFocus Python Client Library](https://github.com/PaloAltoNetworks/autofocus-client-library). The goal of *af_lenz.py* is to build ontop of the client library by providing a set of helpful tools to aide incident responders, or analysts, in rapidly extracting information from AutoFocus that can be used for operational intelligence.

```
python af_lenz.py -h
usage: af_lenz.py [-h] -i <query_type> -q <query> [-o <section_output>]
                  [-f <number>] -r <function_name> [-s <special_output>]
                  [-c <integer_percent>]

Run functions to retrieve information from AutoFocus.

optional arguments:
  -h, --help            show this help message and exit
  -i <query_type>, --ident <query_type>
                        Query identifier type for AutoFocus search. [hash,
                        hash_list, ip, network, dns, file, http, mutex,
                        process, registry, service, user_agent, tag]
  -q <query>, --query <query>
                        Value to query Autofocus for.
  -o <section_output>, --output <section_output>
                        Section of data to return. Multiple values are comma
                        separated (no space) or "all" for everything, which is
                        default. [service, registry, process, misc,
                        user_agent, mutex, http, dns, behavior_type,
                        connection, file, subject, filename, application,
                        country, industry, email]
  -f <number>, --filter <number>
                        Filter out Benign/Grayware/Malware counts over this
                        number, default 10,000.
  -r <function_name>, --run <function_name>
                        Function to run. [uniq_sessions, hash_lookup,
                        common_artifacts, common_pieces, http_scrape,
                        dns_scrape, mutex_scrape]
  -s <special_output>, --special <special_output>
                        Output data formated in a special way for other tools.
                        [yara_rule, af_import]
  -c <integer_percent>, --commonality <integer_percent>
                        Commonality percentage for comparison functions,
                        default is 100
```

### [+] CHANGE LOG [+]

v1.0.2 - 22MAR2016
* Converted over to using _raw_line for everything.

v1.0.1 - 19MAR2016
* Added "query" identifier so you can pass AF queries directly on CLI.
* Added escaping to file/registry supplied queries.

v1.0.0 - 17MAR2016
* Initial release of af_lenz.py.

### [+] FUTURE TO-DOs [+]

In no particular order...
* Code review

### [+] NOTES [+]

Note stuff

### [+] EXAMPLES [+]

Analyzing activity of malware can be very noisy and AutoFocus provides a good way to identify whether something might be noise through the use of the B/G/M system. For each sample with a matching entry for the activity, whether its file, network, or process based, it will be added to a count for benign, grayware, and malicious samples. In this fashion, if a entry has 5 million matches to benign samples, it's likely just noise; that being said, *af_lenz.py* has a built-in filter of 10,000 matches but can be adjusted with the *-f* flag to override it.

To lookup the dynamic analysis (DA) information for a particular sample, specify the identifier for the query as hash, pass the SHA256 hash, and run the "hash_lookup" function. As you'll see, it can be a large amount of data, pipe delimeted, but gives you a quick way to automate or hone in on specifics.

```
python af_lenz.py -i hash -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d -r hash_lookup

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d

[+] registry [+]

sample.exe|SetValueKey|HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\Windows Audio Service,Value:Windows\SysWOW64\svchost_update.exe,Type:1
svchost_update.exe|DeleteValueKey|HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass
svchost_update.exe|DeleteValueKey|HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass
svchost_update.exe|DeleteValueKey|HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\IntranetName
	<TRUNCATED>
ntsystem.exe|RegCreateKeyEx|HKLM,System\CurrentControlSet\Services\Tcpip\Parameters
netsh.exe|RegSetValueEx|HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List,WINDOWS\system32\ntsystem.exe,WINDOWS\system32\ntsystem.exe:*:Enabled:Windows ClipBook
ntsystem.exe|RegSetValueEx|HKCU\Software\pb,id,1494421186
ntsystem.exe|RegSetValueEx|HKCU\Software\pb,hl,aHR0cDovL21pYmVycG9ydGVzYWwuY29tL2dvLnBocA==

[+] process [+]

sample.exe|created|,Windows\SysWOW64\svchost_update.exe, Windows\SysWOW64\svchost_update.exe
svchost_update.exe|created|,Windows\SysWOW64\netsh.exe, Windows\System32\netsh.exe  firewall add allowedprogram  Windows\SysWOW64\svchost_update.exe   Windows Audio Service  ENABLE
svchost_update.exe|terminated|,Windows\SysWOW64\netsh.exe
None|terminated|,Windows\SysWOW64\svchost_update.exe
	<TRUNCATED>
ntsystem.exe|LoadLibraryExW|DNSAPI.dll,,0
ntsystem.exe|LoadLibraryExW|rasadhlp.dll,,0
ntsystem.exe|LoadLibraryExW|hnetcfg.dll,,0
ntsystem.exe|LoadLibraryExW|WINDOWS\System32\wshtcpip.dll,,0

[+] misc [+]

svchost_update.exe|SetWindowLong|SystemProcess,GWL_WNDPROC
svchost_update.exe|IsDebuggerPresent|
ntsystem.exe|SetWindowLong|SystemProcess,GWL_WNDPROC

[+] user_agent [+]

pb

[+] mutex [+]

svchost_update.exe|CreateMutexW|Local\!IETld!Mutex
ntsystem.exe|CreateMutexW|c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
ntsystem.exe|CreateMutexW|c:!documents and settings!administrator!cookies!
ntsystem.exe|CreateMutexW|c:!documents and settings!administrator!local settings!history!history.ie5!
ntsystem.exe|CreateMutexW|WininetConnectionMutex
ntsystem.exe|CreateMutexW|<NULL>

[+] http [+]

markovqwesta.com|GET|/que.php|pb
markovqwesta.com|GET|/que.php|pb
93.189.40.225|GET|/wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW|

[+] dns [+]

markovqwesta.com|193.235.147.11|A
iholpforyou4.com||NXDOMAIN
markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS
iholpforyou4.com||NXDOMAIN
markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns3.cnmsn.com|NS

[+] behavior_type [+]

process
unknown_traffic
nx_domain
registry
autostart
ie_security
malware_domain
	<TRUNCATED>
external_netsh
http_direct_ip
copy_itself
sus_ua
unpack_write_section
malware_url

[+] connection [+]

None|connect|tcp|193.235.147.11:80|SE
ntsystem.exe|connect|tcp|93.189.40.225:80|RU
ntsystem.exe|connect|tcp|193.235.147.11:80|SE
ntsystem.exe|connect|tcp|46.165.222.212:9505|DE
ntsystem.exe|connect|tcp|46.165.222.212:495|DE

[+] file [+]

sample.exe|Write|Windows\SysWOW64\9125y5yta.dat
sample.exe|Create|Windows\SysWOW64\svchost_update.exe
sample.exe|Write|Windows\SysWOW64\svchost_update.exe
svchost.exe|Write|Windows\System32\wdi\{86432a0b-3c7d-4ddf-a89c-172faa90485d}\{d873ef00-5982-4c2b-8a78-ea57c88fbba1}\snapshot.etl
	<TRUNCATED>
None|create|C:\Documents and Settings\Administrator\Local Settings\Temp\df4.tmp.exe
None|create|C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\LDKH2A5D\book[2].htm
None|create|C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\VPKKM73P\book[2].htm
None|delete|C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5\K1XHOOEA\book[1].htm

[+] processed 1 hashes with a BGM filter of 10000 [+]
```

You can also use the *-o* flag to specify only the sections of output you're interested in.

```
python af_lenz.py -i hash -q 232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d -r hash_lookup -o http,dns,connection

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d

[+] http [+]

markovqwesta.com|GET|/que.php|pb
markovqwesta.com|GET|/que.php|pb
93.189.40.225|GET|/wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW|

[+] dns [+]

markovqwesta.com|193.235.147.11|A
iholpforyou4.com||NXDOMAIN
markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS
iholpforyou4.com||NXDOMAIN
markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns3.cnmsn.com|NS

[+] connection [+]

None|connect|tcp|193.235.147.11:80|SE
ntsystem.exe|connect|tcp|93.189.40.225:80|RU
ntsystem.exe|connect|tcp|193.235.147.11:80|SE
ntsystem.exe|connect|tcp|46.165.222.212:9505|DE
ntsystem.exe|connect|tcp|46.165.222.212:495|DE

[+] processed 1 hashes with a BGM filter of 10000 [+]
```

Using the previous data, we see an HTTP request that looks interesting and want to investigate further. It can be very cumbersome to go through multiple samples, so the "common_artifacts" function can be run to compare every sample and report back only items that exist across the set. For this query, we are matching any samples that contain the domain in question.

```
python af_lenz.py -i http -q markovqwesta.com -r common_artifacts

{"operator":"all","children":[{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
	<TRUNCATED>
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099

[+] dns [+]

markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS

[+] processed 10 hashes with a BGM filter of 10000 [+]
```

One problem with DA is that, by its very nature, its dynamic and has the potential to provide inconsistent results - malware may not run due to certain features being enabled, software being installed, so on and so forth. Continuing with the previous example, instead of a 100% match across all samples, we'll loosen it up to matches across 70% of the set.

```
python af_lenz.py -i http -q markovqwesta.com -r common_artifacts -c 70

{"operator":"all","children":[{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
	<TRUNCATED>
f1485e53403de8c654783ce3e0adf754639542e41c2a89b92843ce8ecdeb4646
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099

[+] user_agent [+]

pb

[+] http [+]

markovqwesta.com|GET|/que.php|pb

[+] dns [+]

markovqwesta.com|ns4.cnmsn.com|NS
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns3.cnmsn.com|NS

[+] connection [+]

None|connect|tcp|193.235.147.11:80|SE

[+] file [+]

sample.exe|CopyFileEx|documents and settings\administrator\sample.exe
sample.exe|CopyFileEx|Users\Administrator\sample.exe

[+] processed 10 hashes with a BGM filter of 10000 [+]
```

The "common_pieces" function, which is the similar to the "common_artifacts" function, further breaks up each entry into individual pieces. This is beneficial when malware might inject into random processes or use unique names each time that won't match across samples. All comparison functions can use the *-c* flag to specify the commonality match percentage. In this next query we are search for common pieces for samples matching the Unit 42 Locky tag with a commonality match of 90%.

```
python af_lenz.py -i tag -q Unit42.Locky -r common_pieces -c 90

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]}]}

[+] hashes [+]

e720f917cd8a02b0372b85068844e132c42ea2c97061b81d378b5a73f9344003
a486ff7e775624da2283ede1d3959c784afe476b0a69ce88cd12c7238b15c9e6
    <TRUNCATED>
13bd70822009e07f1d0549e96b8a4aec0ade07bea2c28d42d782bacc11259cf5
b7a593e6b7813d9fc40f435ffe9b080cd0975b05bc47f1e733870fc0af289fdd

[+] registry [+]

HKCU\Software\Locky\completed,Value:1,Type:4
HKCU\Software\Locky\id,Value:B775A1E4A8880055,Type:1
RegSetValueEx
HKCU,Software\Locky
HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache\WINDOWS\system32\shimgvw.dll,Value:Windows Picture and Fax Viewer,Type:1
HKCU\Control Panel\Desktop\WallpaperStyle,Value:0,Type:1
taskeng.exe
HKCU\Software\Locky,pubkey
HKCU\Software\Locky,paytext
SearchIndexer.exe
HKCU\Control Panel\Desktop\TileWallpaper,Value:0,Type:1
SetValueKey
HKCU\Software\Locky\paytext,-1,Type:3
HKCU\Software\Locky\pubkey,-1,Type:3
HKCU\Software\Locky,id,B775A1E4A8880055
HKCU\Software\Locky,id,74E269BA6A4EF224
SetKeySecurity
RegCreateKeyEx
svchost.exe
HKCU\Software\Locky,completed,1
HKCU\Software\Locky\id,Value:74E269BA6A4EF224,Type:1
DeleteValueKey

[+] process [+]

windows\system32\vssadmin.exe,E23DD973E1444684EB36365DEFF1FC74,4DE7FA20E3224382D8C4A81017E5BDD4673AFBEF9C0F017E203D7B78977FBF8C
windows\system32\notepad.exe,F2C7BB8ACC97F92E987A2D4087D021B1,142E1D688EF0568370C37187FD9F2351D7DDEDA574F8BFA9B0FA4EF42DB85AA2
created
,Windows\System32\notepad.exe, Windows\system32\NOTEPAD.EXE  Users\Administrator\Desktop\_Locky_recover_instructions.txt
windows\system32\vssadmin.exe,CDF76989D9FE20B7CC79C9C3F7BA2D4C,5BCC6E5537ACBC3F36A00546F1300F2601E9152CEE4914ACBA00E2A96481DCF9
,WINDOWS\system32\notepad.exe, WINDOWS\system32\NOTEPAD.EXE  Documents and Settings\Administrator\Desktop\_Locky_recover_instructions.txt
,<null>,vssadmin.exe Delete Shadows /All /Quiet
vssadmin.exe
svchost.exe
,WINDOWS\system32\rundll32.exe,rundll32.exe WINDOWS\system32\shimgvw.dll ImageView_Fullscreen Documents and Settings\Administrator\Desktop\_Locky_recover_instructions.bmp
,WINDOWS\system32\NOTEPAD.EXE,WINDOWS\system32\NOTEPAD.EXE Documents and Settings\Administrator\Desktop\_Locky_recover_instructions.txt
LoadLibraryExW
CreateToolhelp32Snapshot
Windows\system32\MSCTF.dll,,8
,WINDOWS\system32\rundll32.exe, rundll32.exe  WINDOWS\system32\shimgvw.dll,ImageView_Fullscreen Documents and Settings\Administrator\Desktop\_Locky_recover_instructions.bmp
NOTEPAD.EXE
4,vssadmin.exe
,Windows\system32\NOTEPAD.EXE,Windows\system32\NOTEPAD.EXE Users\Administrator\Desktop\_Locky_recover_instructions.txt
,WINDOWS\system32\vssadmin.exe
hash
CreateProcessInternalW
,WINDOWS\system32\vssadmin.exe,vssadmin.exe Delete Shadows /All /Quiet
terminated

[+] http [+]

/main.php
POST

[+] behavior_type [+]

file
sys_folder
external_dll
process
autostart
open_process_dup_handle
browser_proxy
registry
http_post
pending_file_rename
external_cmd
external_control_panel
ie_connection
create_doc_exe

[+] connection [+]

tcp
connect
None

[+] file [+]

Users\Public\Pictures\Sample Pictures\Chrysanthemum.jpg
C:\Users\Administrator\Desktop\_Locky_recover_instructions.txt
Documents and Settings\All Users\Documents\My Pictures\Sample Pictures\Blue hills.jpg
Documents and Settings\Administrator\Cookies\_Locky_recover_instructions.txt
    <TRUNCATED>
Documents and Settings\Administrator\Cookies\administrator@red[2].txt
Users\Public\Pictures\Sample Pictures\Lighthouse.jpg
Documents and Settings\All Users\Documents\My Music\Sample Music\_Locky_recover_instructions.txt
Documents and Settings\Administrator\My Documents\password_list.txt

[+] processed 1251 hashes with a BGM filter of 10000 [+]
```

In addition to the comparison functions, there are scraping functions which will iterate over each sample identified and return all unique data in their respective sections. Below are all HTTP requests made by samples with a IP in their DNS section (resolved to).

```
python af_lenz.py -i dns -q 193.235.147.11 -r http_scrape

{"operator":"all","children":[{"field":"alias.domain","operator":"contains","value":"193.235.147.11"}]}

[+] hashes [+]

232c8369c1ac8a66d52df294519298b4bcc772e7bed080c38ac141ad1928894d
cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03
    <TRUNCATED>
23e9815fe25321b0349e8c6fc22473914a306d27a9d8cae2872396cf7a14c099
118577d6c021c14cbd9c7226475c982d2ce230568295b86f3104860e544f7317

[+] http [+]

http://markovqwesta.com/que.php
http://93.189.40.225/wp-trackback.php?proxy=46.165.222.212%3A9506&secret=BER5w4evtjszw4MBRW
http://iholpforyou4.com/d_index.php
http://80.78.242.47/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW
http://truedonell.com/fa.php
http://93.189.40.225/xp.php?proxy=5.79.85.212%3A44495&secret=BER5w4evtjszw4MBRW
http://hostnamessimply1.effers.com/
http://go.microsoft.com/fwlink/?LinkId=164164
http://www.msn.com/
http://93.189.40.225/xp.php?proxy=46.165.223.193%3A2238&secret=BER5w4evtjszw4MBRW
http://www.adobe.com/go/flashplayer_support/
http://support.microsoft.com/
http://93.189.40.225/xp.php?proxy=46.165.222.212%3A2308&secret=BER5w4evtjszw4MBRW
http://go.microsoft.com/fwlink/?LinkId=120337
http://go.microsoft.com/fwlink/?LinkId=98073
http://93.189.40.225/wp-trackback.php?proxy=93.189.42.43%3A1637&secret=BER5w4evtjszw4MBRW
http://93.189.40.196/i.php?proxy=104.238.173.238%3A5577&secret=BER5w4evtjszw4MBRW
http://93.189.40.196/i.php?proxy=93.189.42.43%3A13850&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=185.72.246.23%3A38744&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=108.59.9.15%3A20461&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/xp.php?proxy=213.229.102.157%3A10720&secret=BER5w4evtjszw4MBRW
http://80.78.242.47/pointer.php?proxy=69.64.32.110%3A6461&secret=BER5w4evtjszw4MBRW
http://80.78.242.47/pointer.php?proxy=91.185.215.141%3A4773&secret=BER5w4evtjszw4MBRW
http://smic12wer.com/12.php
http://smic12wer.com/post.php?command=update2&id=1494432142&ip=93.189.40.164&port=17292
http://93.189.40.225/xp.php?proxy=46.38.51.49%3A14527&secret=BER5w4evtjszw4MBRW
http://80.78.242.47/pointer.php?proxy=46.38.51.49%3A38388&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=185.72.244.171%3A3398&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=108.59.9.15%3A6232&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=185.72.244.171%3A40240&secret=BER5w4evtjszw4MBRW
http://93.189.40.225/wp-trackback.php?proxy=108.59.9.15%3A14542&secret=BER5w4evtjszw4MBRW
http://80.78.242.47/pointer.php?proxy=194.247.12.49%3A27123&secret=BER5w4evtjszw4MBRW
http://80.78.242.47/pointer.php?proxy=69.64.32.110%3A23622&secret=BER5w4evtjszw4MBRW
http://93.189.40.196/i.php?proxy=46.38.51.49%3A32045&secret=BER5w4evtjszw4MBRW
http://66.85.139.195/phinso.php?proxy=46.165.222.212%3A29786&secret=BER5w4evtjszw4MBRW

[+] processed 17 hashes with a BGM filter of 10000 [+]
```

DNS scrape of three hashes pasted as a comma separated list.

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

```
python af_lenz.py -i mutex -q M_Test -r uniq_sessions

{"operator":"all","children":[{"field":"sample.tasks.mutex","operator":"contains","value":"M_Test"}]}

[+] filename [+]

ac90c24e-f340-4bb3-b94f-b39693b843f6_725bb9e4ac0460ce71538a1de652b19a55cfbc9a84f0ecdd22b62d9f6c0eef7b
851e90328473bca6b8fad472f16e0bd1
658eac09b4e0e4e7e9c05eeb07a5c3109096a66ee9308abde5fb5525a5ed8b90.file
99e5a43d-fcf1-4439-adb6-29d10078d641_736769a19751f28f9551953f4765b1308c60aeda7b90e1e672a154a8580f82a7
605f3468324fceef696d814d29de4047e38af278eac5deab8803cd75bbda6e64.file
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
Manufacturing
Higher Education
Wholesale and Retail
Government
Hospitality

[+] processed 863 sessions [+]
```

The above shows a varied distribution throughout industry and country (non-targeted most likely), and some additional filenames you may want to search for.

Last, there are a few special ways you can take the data returned from the functions and output them for other tools. Below is creating a yara rule out of 4 sections of DA for a hash.

```
python af_lenz.py -i hash -q cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03 -o connection,dns,http,mutex -r hash_lookup -s yara_rule

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03"}]}

[+] hashes [+]

cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03

[+] connection [+]

winlsm.exe|connect|tcp|91.185.215.141:989|SI
winlsm.exe|connect|tcp|193.235.147.11:80|SE
winlsm.exe|connect|tcp|46.36.221.85:80|EU
smss-mon.exe|connect|tcp|193.235.147.11:80|SE
smss-mon.exe|connect|tcp|46.36.221.85:80|EU
smss-mon.exe|connect|tcp|217.172.179.88:989|DE
smss-mon.exe|connect|tcp|217.172.179.88:14450|DE
smss-mon.exe|connect|tcp|80.78.242.47:80|RU

[+] dns [+]

iholpforyou4.com|46.36.221.85|A
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns3.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS
iholpforyou4.com|46.36.221.85|A
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns3.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS

[+] http [+]

markovqwesta.com|GET|/que.php|pb
iholpforyou4.com|GET|/d_index.php|pb
iholpforyou4.com|GET|/d_index.php|pb
80.78.242.47|GET|/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW|
markovqwesta.com|GET|/que.php|pb

[+] mutex [+]

winlsm.exe|CreateMutexW|Local\!IETld!Mutex
winlsm.exe|CreateMutexW|IESQMMUTEX_0_208
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!cookies!
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!local settings!history!history.ie5!
smss-mon.exe|CreateMutexW|WininetConnectionMutex
smss-mon.exe|CreateMutexW|<NULL>

[+] processed 1 hashes with a BGM filter of 10000 [+]

[+] yara sig [+]

rule generated_by_afIR
{
	strings:
		$connection_0 = "91.185.215.141"
		$connection_1 = "193.235.147.11"
		$connection_2 = "46.36.221.85"
		$connection_3 = "193.235.147.11"
		$connection_4 = "46.36.221.85"
		$connection_5 = "217.172.179.88"
		$connection_6 = "217.172.179.88"
		$connection_7 = "80.78.242.47"
		$dns_0 = "iholpforyou4.com"
		$dns_2 = "markovqwesta.com"
		$dns_5 = "ns4.cnmsn.com"
		$dns_9 = "ns3.cnmsn.com"
		$http_1 = "/que.php"
		$http_4 = "/d_index.php"
		$http_10 = "/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW"

	condition:
		1 of ($connection*, $dns*) /* Adjust as needed for accuracy */
}
```

You can also build an AutoFocus query based on the output.

```
python af_lenz.py -i hash -q cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03 -o connection,dns,http,mutex -r hash_lookup -s af_import

{"operator":"all","children":[{"field":"sample.sha256","operator":"is","value":"cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03"}]}

[+] hashes [+]

cda1be0cee01aa74518c4e6eca4a4ecf8fae7ed13fa8f392d88988a5ac76ec03

[+] connection [+]

winlsm.exe|connect|tcp|91.185.215.141:989|SI
winlsm.exe|connect|tcp|193.235.147.11:80|SE
winlsm.exe|connect|tcp|46.36.221.85:80|EU
smss-mon.exe|connect|tcp|193.235.147.11:80|SE
smss-mon.exe|connect|tcp|46.36.221.85:80|EU
smss-mon.exe|connect|tcp|217.172.179.88:989|DE
smss-mon.exe|connect|tcp|217.172.179.88:14450|DE
smss-mon.exe|connect|tcp|80.78.242.47:80|RU

[+] dns [+]

iholpforyou4.com|46.36.221.85|A
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns3.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS
iholpforyou4.com|46.36.221.85|A
markovqwesta.com|193.235.147.11|A
markovqwesta.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns4.cnmsn.com|NS
iholpforyou4.com|ns3.cnmsn.com|NS
markovqwesta.com|ns3.cnmsn.com|NS

[+] http [+]

markovqwesta.com|GET|/que.php|pb
iholpforyou4.com|GET|/d_index.php|pb
iholpforyou4.com|GET|/d_index.php|pb
80.78.242.47|GET|/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW|
markovqwesta.com|GET|/que.php|pb

[+] mutex [+]

winlsm.exe|CreateMutexW|Local\!IETld!Mutex
winlsm.exe|CreateMutexW|IESQMMUTEX_0_208
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!cookies!
smss-mon.exe|CreateMutexW|c:!documents and settings!administrator!local settings!history!history.ie5!
smss-mon.exe|CreateMutexW|WininetConnectionMutex
smss-mon.exe|CreateMutexW|<NULL>

[+] processed 1 hashes with a BGM filter of 10000 [+]

[+] af import query [+]

{"operator":"all","children":[{"field":"sample.tasks.connection","operator":"contains","value":"91.185.215.141:989"},{"field":"sample.tasks.connection","operator":"contains","value":"193.235.147.11:80"},{"field":"sample.tasks.connection","operator":"contains","value":"46.36.221.85:80"},{"field":"sample.tasks.connection","operator":"contains","value":"193.235.147.11:80"},{"field":"sample.tasks.connection","operator":"contains","value":"46.36.221.85:80"},{"field":"sample.tasks.connection","operator":"contains","value":"217.172.179.88:989"},{"field":"sample.tasks.connection","operator":"contains","value":"217.172.179.88:14450"},{"field":"sample.tasks.connection","operator":"contains","value":"80.78.242.47:80"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,46.36.221.85,A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,193.235.147.11,A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,ns4.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,ns4.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,ns3.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,ns3.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,46.36.221.85,A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,193.235.147.11,A"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,ns4.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,ns4.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"iholpforyou4.com,ns3.cnmsn.com,NS"},{"field":"sample.tasks.dns","operator":"contains","value":"markovqwesta.com,ns3.cnmsn.com,NS"},{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com,GET,/que.php,pb"},{"field":"sample.tasks.http","operator":"contains","value":"iholpforyou4.com,GET,/d_index.php,pb"},{"field":"sample.tasks.http","operator":"contains","value":"iholpforyou4.com,GET,/d_index.php,pb"},{"field":"sample.tasks.http","operator":"contains","value":"80.78.242.47,GET,/pointer.php?proxy=217.172.179.88%3A14452&secret=BER5w4evtjszw4MBRW,"},{"field":"sample.tasks.http","operator":"contains","value":"markovqwesta.com,GET,/que.php,pb"},{"field":"sample.tasks.mutex","operator":"contains","value":"winlsm.exe,CreateMutexW,Local\\!IETld!Mutex"},{"field":"sample.tasks.mutex","operator":"contains","value":"winlsm.exe,CreateMutexW,IESQMMUTEX_0_208"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe,CreateMutexW,c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe,CreateMutexW,c:!documents and settings!administrator!cookies!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe,CreateMutexW,c:!documents and settings!administrator!local settings!history!history.ie5!"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe,CreateMutexW,WininetConnectionMutex"},{"field":"sample.tasks.mutex","operator":"contains","value":"smss-mon.exe,CreateMutexW,<NULL>"}]}
```

You can also send more complex AF queries by passing the "query" value to the *-i* flag. Below we run the "uniq_sessions" function to look at session data for all samples tagged with Locky betwen March 15th-18th that were delivered via web-browsing.

```
python af_lenz.py -i query -q '{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]},{"field":"sample.create_date","operator":"is in the range","value":["2016-03-15T00:00:00","2016-03-18T23:59:59"]},{"field":"session.app","operator":"is","value":"web-browsing"}]}' -r uniq_sessions

{"operator":"all","children":[{"field":"sample.tag","operator":"is in the list","value":["Unit42.Locky"]},{"field":"sample.create_date","operator":"is in the range","value":["2016-03-15T00:00:00","2016-03-18T23:59:59"]},{"field":"session.app","operator":"is","value":"web-browsing"}]}

[+] filename [+]

nbver5w
dh32f
89h8btyfde445.exe
740e6de2613bac3443057574b7ad5464
b2b8d5d6dd1b3c21572279ee3aa40e34
    <TRUNCATED>
508f5770f18098cbe8c14ebb696998ae
98o7kj56h
69b933a694710f8ceb314dc897a94cbe
ce31e5c123842708522c5b8330481345
a02f352bb0f1e0513a7c9cc8428f353b

[+] application [+]

web-browsing

[+] country [+]

Spain
United States
South Africa
Germany
    <TRUNCATED>
Korea Republic Of
Austria
Reserved
Colombia

[+] industry [+]

High Tech
Telecommunications
Professional and Legal Services
Transportation and Logistics
    <TRUNCATED>
Automotive
Finance
Construction
Energy

[+] processed 1812 sessions [+]
```_ 