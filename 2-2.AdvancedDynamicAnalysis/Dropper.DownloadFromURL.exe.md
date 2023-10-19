# Dropper.DownloadFromURL.exe

## Identification:

**FileName:** Malware.Unknown.exe

**SHA256:** 92730427321A1C4CCFC0D0580834DAEF98121EFA9BB8963DA332BFD6CF1FDA8A

**FileSize:** 12288 (bytes)

<br>

## Analysis:

### Basic Static Analysis:

For the initial triage, the file was loaded in PEStudio as shown below. 

<image src="../Images/Dropper.DownloadFromURL.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Followings were found:
- The entropy of this sample was low (5.719 out of 8) so the sample is not packed.
- The sample was written in C++
- The sampole is 32-bit and has CLI interface.
- The sample was compiled on Sat Sep 04 11:11:12 2021.

<br>

Then using capa tool, the sample was analyzed to check its behavior with the command:

`capa  Malware.Unknown.exe`

    +------------------------+------------------------------------------------------------------------------------+
    | ATT&CK Tactic          | ATT&CK Technique                                                                   |
    |------------------------+------------------------------------------------------------------------------------|
    | EXECUTION              | Shared Modules [T1129]                                                             |
    +------------------------+------------------------------------------------------------------------------------+
    
    +-----------------------------+-------------------------------------------------------------------------------+
    | MBC Objective               | MBC Behavior                                                                  |
    |-----------------------------+-------------------------------------------------------------------------------|
    | COMMAND AND CONTROL         | C2 Communication::Receive Data [B0030.002]                                    |
    | COMMUNICATION               | HTTP Communication::Create Request [C0002.012]                                |
    |                             | HTTP Communication::Download URL [C0002.006]                                  |
    |                             | HTTP Communication::Open URL [C0002.004]                                      |
    | PROCESS                     | Create Process [C0017]                                                        |
    |                             | Terminate Process [C0018]                                                     |
    +-----------------------------+-------------------------------------------------------------------------------+
    
    +------------------------------------------------------+------------------------------------------------------+
    | CAPABILITY                                           | NAMESPACE                                            |
    |------------------------------------------------------+------------------------------------------------------|
    | receive data                                         | communication                                        |
    | connect to URL                                       | communication/http/client                            |
    | contains PDB path                                    | executable/pe/pdb                                    |
    | contain a resource (.rsrc) section                   | executable/pe/section/rsrc                           |
    | create process (2 matches)                           | host-interaction/process/create                      |
    | terminate process                                    | host-interaction/process/terminate                   |
    | terminate process via fastfail (2 matches)           | host-interaction/process/terminate                   |
    | parse PE header (2 matches)                          | load-code/pe                                         |
    +------------------------------------------------------+------------------------------------------------------+

- The sample will reach to its C2 to request and download some file.
- The sample will create some process, most likely to execute the downloaded file.
- The sample will terminate process, most likely itself when it cannot reach the C2.

<br>

Then the strings were checked using the FLOSS tool with the command:

`floss.exe Malware.Unknown.ex`

The interesting strings found were:

    C:\Users\Matt\source\repos\HuskyHacks\PMAT-maldev\src\DownloadFromURL\Release\DownloadFromURL.pdb
    cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q "%s"
    http://ssl-6582datamanager.helpdeskbros.local/favicon.ico
    C:\Users\Public\Documents\CR433101.dat.exe
    Mozilla/5.0
    http://huskyhacks.dev
    ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\Users\Public\Documents\CR433101.dat.exe
    open

- Some interesting commands as well as URL were found in the strings.

<br>

### Basic Dynamic Analysis:

The sample was then executed for dynamic analysis. Before execution of samples, tools like Process Monitor, Process Explorer and Wireshark were also runned for behavior analysis. 

The sample was then executed for dynamic analysis. On execution, it try to reach ssl-6582datamanager[.]helpdeskbros[.]local as shown in the Wireshark capture below. Since the lab was isolated with no network simulation active, the resolution to that domain fail making the sample unable to reach it.

<image src="../Images/Dropper.DownloadFromURL.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After the sample failed to reach ssl-6582datamanager[.]helpdeskbros[.]local, it deleted itself as shown in Process Monitor capture.

<image src="../Images/Dropper.DownloadFromURL.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

Now in Remnux machine, INetSim was runned for network simulation. 

<image src="../Images/putty.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that the sample was executed again. This time, the sample again try to reach ssl-6582datamanager[.]helpdeskbros[.]local and successfully resolute to IP of the Remnux machine and start connection over port 80. The sample then requested favicon.ico over HTTP. After that it tried to reach huskyhacks[.]dev. This all were discovered in the Wireshark capture as shown below.

<image src="../Images/Dropper.DownloadFromURL.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

In the Process Monitor capture, it was found that the requested file favicon.ico was first cached temporarily. Also the sample had saved CR433101.dat.exe under Public Documents which could actually be the requested favicon.ico. This can be further verified during advanced dynamic analysis by debugging.

<image src="../Images/Dropper.DownloadFromURL.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The CR433101.dat.exe dropped under Public Document was also verified.

<image src="../Images/Dropper.DownloadFromURL.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

This sample capabilities will be unraveled in detail in the following advanced analysis sections.

<br>

### Advanced Static Analysis:



<br>

### Advanced Dynamic Analysis:


<br>

## Indicator of Compromise 

### Host-based Indicators


### Network-based Indicators


<br>

## Detection with YARA Rule:


