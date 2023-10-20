# unknown.exe

## Identification:

**FileName:** unknown.exe

**SHA256:** 

**FileSize:** 561152 (bytes)

<br>

## Analysis:

### Basic Static Analysis:

For the initial triage, the file was loaded in PEStudio as shown below. 

<image src="../Images/unknown.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Followings were found:
- The entropy of this sample was low (6.080 out of 8) so the sample is not packed.
- The sample is 64-bit and has GUI interface.
- The sample was compiled on Sat Jan 08 13:29:18 2022.

<br>

Then using capa tool, the sample was analyzed to check its behavior with the command:

`capa  unknown.exe`

    +------------------------+------------------------------------------------------------------------------------+
    | ATT&CK Tactic          | ATT&CK Technique                                                                   |
    |------------------------+------------------------------------------------------------------------------------|
    | DEFENSE EVASION        | Obfuscated Files or Information [T1027]                                            |
    | DISCOVERY              | File and Directory Discovery [T1083]                                               |
    |                        | System Information Discovery [T1082]                                               |
    | EXECUTION              | Shared Modules [T1129]                                                             |
    +------------------------+------------------------------------------------------------------------------------+
    
    +-----------------------------+-------------------------------------------------------------------------------+
    | MBC Objective               | MBC Behavior                                                                  |
    |-----------------------------+-------------------------------------------------------------------------------|
    | ANTI-BEHAVIORAL ANALYSIS    | Debugger Detection::Software Breakpoints [B0001.025]                          |
    | DATA                        | Check String [C0019]                                                          |
    |                             | Checksum::Luhn [C0032.002]                                                    |
    |                             | Encoding::Base64 [C0026.001]                                                  |
    |                             | Non-Cryptographic Hash::MurmurHash [C0030.001]                                |
    | DEFENSE EVASION             | Obfuscated Files or Information::Encoding-Standard Algorithm [E1027.m02]      |
    | FILE SYSTEM                 | Read File [C0051]                                                             |
    |                             | Write File [C0052]                                                            |
    | MEMORY                      | Allocate Memory [C0007]                                                       |
    | PROCESS                     | Terminate Process [C0018]                                                     |
    +-----------------------------+-------------------------------------------------------------------------------+
    
    +------------------------------------------------------+------------------------------------------------------+
    | CAPABILITY                                           | NAMESPACE                                            |
    |------------------------------------------------------+------------------------------------------------------|
    | check for software breakpoints                       | anti-analysis/anti-debugging/debugger-detection      |
    | compiled with Nim                                    | compiler/nim                                         |
    | validate payment card number using luhn algorithm    | data-manipulation/checksum/luhn                      |
    | encode data using Base64                             | data-manipulation/encoding/base64                    |
    | reference Base64 string                              | data-manipulation/encoding/base64                    |
    | hash data using murmur3 (2 matches)                  | data-manipulation/hashing/murmur                     |
    | contain a resource (.rsrc) section                   | executable/pe/section/rsrc                           |
    | contain a thread local storage (.tls) section        | executable/pe/section/tls                            |
    | query environment variable                           | host-interaction/environment-variable                |
    | check if file exists                                 | host-interaction/file-system/exists                  |
    | read file (2 matches)                                | host-interaction/file-system/read                    |
    | write file (4 matches)                               | host-interaction/file-system/write                   |
    | get thread local storage value                       | host-interaction/process                             |
    | allocate RWX memory                                  | host-interaction/process/inject                      |
    | terminate process                                    | host-interaction/process/terminate                   |
    | parse PE header (2 matches)                          | load-code/pe                                         |
    +------------------------------------------------------+------------------------------------------------------+

- The sample is written in Nim.
- The sample has Base64 encoded strings.
- The sample has seems to have anti-debugging technique in it.

<br>

Then the strings were checked using the FLOSS tool with the command:

`floss.exe unknown.ex`

The interesting strings found were:

    @Mozilla/5.0
    @C:\Users\Public\passwrd.txt
    @http://cdn.altimiter.local/feed?post=

- Strings relating to user agent, some passwrd.txt under Public and domain were found. 

### Basic Dynamic Analysis:

The sample was then executed for dynamic analysis. On execution, it try to reach update[.]ec12-4-109-278-3-ubuntu20-04[.]local as shown in the Wireshark capture below. Since the lab was isolated with no network simulation active, the resolution to that domain fail making the sample unable to reach it.

<image src="../Images/unknown.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After the sample failed to reach update[.]ec12-4-109-278-3-ubuntu20-04[.]local, it deleted itself as shown in Process Monitor capture.

<image src="../Images/unknown.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

Now in Remnux machine, INetSim was runned for network simulation. 

<image src="../Images/putty.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that the sample was executed again. This time, the sample again try to reach update[.]ec12-4-109-278-3-ubuntu20-04[.]local and successfully resolute to IP of the Remnux machine and start connection over port 

<image src="../Images/unknown.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

In the Process Monitor capture, it was found that 

