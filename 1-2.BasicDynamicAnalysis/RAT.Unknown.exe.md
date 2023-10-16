# RAT.Unknown.exe

## Identification:

**FileName:** RAT.Unknown.exe

**SHA256:** 248D491F89A10EC3289EC4CA448B19384464329C442BAC395F680C4F3A345C8C

**FileSize:** 520192 (bytes)

<br>

## Analysis:

### Static Analysis


`capa RAT.Unknown.exe`

    +------------------------+------------------------------------------------------------------------------------+
    | ATT&CK Tactic          | ATT&CK Technique                                                                   |
    |------------------------+------------------------------------------------------------------------------------|
    | DISCOVERY              | System Information Discovery [T1082]                                               |
    | EXECUTION              | Shared Modules [T1129]                                                             |
    | PERSISTENCE            | Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]  |
    +------------------------+------------------------------------------------------------------------------------+
    
    +-----------------------------+-------------------------------------------------------------------------------+
    | MBC Objective               | MBC Behavior                                                                  |
    |-----------------------------+-------------------------------------------------------------------------------|
    | DATA                        | Check String [C0019]                                                          |
    |                             | Encoding::Base64 [C0026.001]                                                  |
    |                             | Non-Cryptographic Hash::MurmurHash [C0030.001]                                |
    | FILE SYSTEM                 | Write File [C0052]                                                            |
    | MEMORY                      | Allocate Memory [C0007]                                                       |
    | PROCESS                     | Terminate Process [C0018]                                                     |
    +-----------------------------+-------------------------------------------------------------------------------+
    
    +------------------------------------------------------+------------------------------------------------------+
    | CAPABILITY                                           | NAMESPACE                                            |
    |------------------------------------------------------+------------------------------------------------------|
    | compiled with Nim                                    | compiler/nim                                         |
    | reference Base64 string                              | data-manipulation/encoding/base64                    |
    | hash data using murmur3 (2 matches)                  | data-manipulation/hashing/murmur                     |
    | contain a resource (.rsrc) section                   | executable/pe/section/rsrc                           |
    | contain a thread local storage (.tls) section        | executable/pe/section/tls                            |
    | query environment variable                           | host-interaction/environment-variable                |
    | write file (3 matches)                               | host-interaction/file-system/write                   |
    | get thread local storage value                       | host-interaction/process                             |
    | allocate RWX memory                                  | host-interaction/process/inject                      |
    | terminate process                                    | host-interaction/process/terminate                   |
    | parse PE header (2 matches)                          | load-code/pe                                         |
    | reference startup folder                             | persistence/startup-folder                           |
    +------------------------------------------------------+------------------------------------------------------+

- Written in Nim
- Has Base64 encoded strings
- May have persistence by adding under Run key or start-up folder


<image src="../Images/RAT.Unknown.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Compiled on Sun Sep 12 09:30:09 2021

<image src="../Images/RAT.Unknown.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The .text section has low entropy, as well as the size of virtual size and the size of raw size is close. So, it does not seems to be packed. 


Strings

    InternetOpenW
    InternetOpenUrlW
    @[+] what command can I run for you
    @NO SOUP FOR YOU
    @\mscordll.exe
    @Nim httpclient/1.0.6
    @/msdcorelib.exe
    @AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    @http://serv1.ec2-102-95-13-2-ubuntu.local


### Dynamic Analysis

On execution, it try to reach serv1.ec2-102-95-13-2-ubuntu[.]local

<image src="../Images/RAT.Unknown.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

When fail to reach that domain, it exits with message

<image src="../Images/RAT.Unknown.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

INetSim simulation 

After resolution, start connection over 80 and request mscord.dll 

<image src="../Images/RAT.Unknown.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >


<image src="../Images/RAT.Unknown.exe6.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Saves requested mscordll.exe under startup folder 


Furthermore, listen on port 5555 

<image src="../Images/RAT.Unknown.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Connecting to that port, it output some base64 encoded value

<image src="../Images/RAT.Unknown.exe8.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The base64 encoded value was decoded to be '[+] what command can I run for you'

<image src="../Images/RAT.Unknown.exe9.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

A command 'whoami' was entered which again output base64 encoded value, which on decoding was found to be the user of infected host. This verify that it is a RAT.

<image src="../Images/RAT.Unknown.exe10.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<image src="../Images/RAT.Unknown.exe11.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

