# RAT.Unknown2.exe

## Identification:

**FileName:** RAT.Unknown2.exe

**SHA256:** 481EAE82AC4CD1A9CFADC026A628B18D7B4C54F50385D28C505FBCB3E999B8B0

**FileSize:** 453498 (bytes)

<br>

## Analysis:

### Static Analysis

For the initial triage, the sample was loaded in PEStudio as shown below.

<image src="../Images/RAT.Unknown2.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Followings were found:
- The entropy of this sample was low (6.057 out of 8) so the sample is not packed.
- The sample is 64-bit and has GUI interface.
- The sample was compiled on Sat Sep 18 13:21:26 2021.

<br>

Then using capa tool, the sample was analyzed to check its behavior with the command:

`capa RAT.Unknown2.exe`

    +------------------------+------------------------------------------------------------------------------------+
    | ATT&CK Tactic          | ATT&CK Technique                                                                   |
    |------------------------+------------------------------------------------------------------------------------|
    | EXECUTION              | Shared Modules [T1129]                                                             |
    +------------------------+------------------------------------------------------------------------------------+
    
    +-----------------------------+-------------------------------------------------------------------------------+
    | MBC Objective               | MBC Behavior                                                                  |
    |-----------------------------+-------------------------------------------------------------------------------|
    | FILE SYSTEM                 | Write File [C0052]                                                            |
    | MEMORY                      | Allocate Memory [C0007]                                                       |
    | PROCESS                     | Terminate Process [C0018]                                                     |
    +-----------------------------+-------------------------------------------------------------------------------+
    
    +------------------------------------------------------+------------------------------------------------------+
    | CAPABILITY                                           | NAMESPACE                                            |
    |------------------------------------------------------+------------------------------------------------------|
    | compiled with Nim                                    | compiler/nim                                         |
    | contain a resource (.rsrc) section                   | executable/pe/section/rsrc                           |
    | contain a thread local storage (.tls) section        | executable/pe/section/tls                            |
    | write file (3 matches)                               | host-interaction/file-system/write                   |
    | get thread local storage value                       | host-interaction/process                             |
    | allocate RWX memory                                  | host-interaction/process/inject                      |
    | terminate process                                    | host-interaction/process/terminate                   |
    | parse PE header (2 matches)                          | load-code/pe                                         |
    +------------------------------------------------------+------------------------------------------------------+

- The sample is found to be written in Nim

<br>

Then the strings were checked using the FLOSS tool with the command:

`floss.exe RAT.Unknown2.exe`

The interesting strings found were:

    @cmd.exe /c
    @exit
    @.local
    @kadusus
    @Could not send all data.
    @No valid socket error code available
    @cannot write string to file

- Here, strings points that it might spawn cmd instance, connect to some domain '.local' as well as perform some network activity and write something.

<br>

### Dynamic Analysis:

The sample was then executed for dynamic analysis. On execution, it try to reach aaaaaaaaaaaaaaaaaaaa[.]kadusus[.]local as shown in the Wireshark capture below. Since the lab was isolated with no network simulation active, the resolution to that domain fail making the sample unable to reach it. 

<image src="../Images/RAT.Unknown2.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

When the sample fail to reach that domain, it terminated itself as shown in Process Monitor capture.

<image src="../Images/RAT.Unknown2.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

Now in Remnux machine, INetSim was runned for network simulation. 

<image src="../Images/putty.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that the sample was executed again. This time, the sample again try to reach aaaaaaaaaaaaaaaaaaaa[.]kadusus[.]local and successfully resolute to IP of the Remnux machine and start connection over port 443 as shown in Wireshark capture. 

<image src="../Images/RAT.Unknown2.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Here, it can be seen that it will perform 3-way handshake over port 443. But after that there is no activity. It may be because it may open reverse shell connection to port 443 of the IP after resolution of aaaaaaaaaaaaaaaaaaaa[.]kadusus[.]local. And since the INetSim running on Remnux, it is already listening on port 443 so nothing is happening. 

<br>

Lets now use different approach to verify if its the reverse shell. For this, to simulate the domain name, fakedns tool can be used in Remnux as shown below.

<image src="../Images/RAT.Unknown2.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Then again in Remnux machine, netcat was used to listen on the port 443 for possible reverse shell connection as shown below.

<image src="../Images/RAT.Unknown2.exe6.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After this the sample was again executed. After the execution, a connection was recieved on the netcat from the infected Windows machine as shown below.

<image src="../Images/RAT.Unknown2.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

A command 'whoami' was entered which output the user of the infected Windows machine. This verify that it is a RAT.

<image src="../Images/RAT.Unknown2.exe8.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

# Indicator of Compromise:

## Network-based Indicators:
- aaaaaaaaaaaaaaaaaaaa[.]kadusus[.]local

<br>

# Detection with YARA Rule:

    rule RAT_Unknown2_Exe{
        meta:
                author= "Venus Chhantel"
                description= "RAT.Unknown2.exe"
        strings:

                $C2_part1 = "kadusus"
                $C2_part2 = ".local"
    
        condition:
                uint16(0) == 0x5A4D and
                (
                        2 of ($C2*)
                )
        }

