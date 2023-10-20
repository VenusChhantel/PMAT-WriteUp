# RAT.Unknown.exe

## Identification:

**FileName:** RAT.Unknown.exe

**SHA256:** 248D491F89A10EC3289EC4CA448B19384464329C442BAC395F680C4F3A345C8C

**FileSize:** 520192 (bytes)

<br>

## Analysis:

### Basic Static Analysis:

For the initial triage, the sample was loaded in PEStudio as shown below.

<image src="../Images/RAT.Unknown.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Followings were found:
- The entropy of this sample was low (6.057 out of 8) so the sample is not packed.
- The sample is 64-bit and has GUI interface.
- The sample was compiled on Sun Sep 12 09:30:09 2021.

<br>

Then using capa tool, the sample was analyzed to check its behavior with the command:

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

- The sample is written in Nim.
- The sample has Base64 encoded strings.
- The sample may have persistence by adding under Run key or start-up folder.

<br>

Then the strings were checked using the FLOSS tool with the command:

`floss.exe RAT.Unknown.exe`

The interesting strings found were:

    @[+] what command can I run for you
    @NO SOUP FOR YOU
    @\mscordll.exe
    @Nim httpclient/1.0.6
    @/msdcorelib.exe
    @AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    @http://serv1.ec2-102-95-13-2-ubuntu.local

- Strings related to domain, startup path, executable and string asking for commands were found. 

<br>

### Basic Dynamic Analysis:

The sample was then executed for dynamic analysis. On execution, it try to reach serv1[.]ec2-102-95-13-2-ubuntu[.]local as shown in the Wireshark capture below. Since the lab was isolated with no network simulation active, the resolution to that domain fail making the sample unable to reach it.

<image src="../Images/RAT.Unknown.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

When the sample fail to reach that domain, it exited with message 'NO SOUP FOR YOU' as shown below.

<image src="../Images/RAT.Unknown.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

Now in Remnux machine, INetSim was runned for network simulation. 

<image src="../Images/putty.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that the sample was executed again. This time, the sample again try to reach serv1[.]ec2-102-95-13-2-ubuntu[.]local and successfully resolute to IP of the Remnux machine and start connection over port 80 and request 'msdcorelib.exe' as shown in Wireshark capture. 

<image src="../Images/RAT.Unknown.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

In the Process Monitor capture, it can be seen that the sample is saving 'mscordll.exe' under startup folder.  

<image src="../Images/RAT.Unknown.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

It seems like the sample will try to connect to serv1[.]ec2-102-95-13-2-ubuntu[.]local in order to request 'msdcorelib.exe' and downloaded it under startup folder as 'mscordll.exe' so that it's executed everytime during startup as persistance mechanism. Also note that the executable dropped is the INetSim binary not the actual binary.

<br>

Furthermore, when checking the process TCP/IP under Process Explorer, it was listening on port 5555 as shown below. This could actually be a bind shell.

<image src="../Images/RAT.Unknown.exe6.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

To verify it that was bind shell, it was connected to that port from Remnux machine using netcat where it output some base64 encoded value as shown below.

<image src="../Images/RAT.Unknown.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The base64 encoded value was decoded to be '[+] what command can I run for you'.

<image src="../Images/RAT.Unknown.exe8.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

A command 'whoami' was entered which again output base64 encoded value, which on decoding was found to be the user of infected host. This verify that it is a RAT.

<image src="../Images/RAT.Unknown.exe9.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<image src="../Images/RAT.Unknown.exe10.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

# Indicator of Compromise:

## Network-based Indicators:
- serv1.ec2-102-95-13-2-ubuntu.local
- The msdcorelib.exe requested over HTTP.

## Host-based Indicators:
- The mscordll.exe dropped under startup folder.

<br>

# Detection with YARA Rule:

    rule RAT_Unknown_Exe{
        meta:
                author= "Venus Chhantel"
                description= "RAT.Unknown.exe"
        strings:
                $file1 = "mscordll.exe"
                $file2 = "msdcorelib.exe"
                $message = "what command can I run for you"
                $C2 = "serv1.ec2-102-95-13-2-ubuntu.local"
    
        condition:
                uint16(0) == 0x5A4D and
                (
                        any of ($file*) and
                        $message and
                        $C2
                )
        }
