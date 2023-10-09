# simpleAntiAnalysis-cpp.exe

## Identification:

**FileName:** simpleAntiAnalysis-cpp.exe

**SHA256:** 0E6F55F4E5D913C734D30C7C43C15628FC6DBA56FA9FDF683462B991C854D3A7

**FileSize:** 319923 (bytes)

<br>

## Analysis:

The sample was loaded in Cutter and then was jumped to WinMin function as shown below.

<image src="../Images/simpleAntiAnalysis-cpp.exe.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

First there is call to **IsDebuggerPresent** windows API. The return value of it will be non-zero if running in debugger or else the return value will be 0. 

**Documentation:** https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent

<br>

### First Case: With Debugger

when the sample is being debugged, the return value from **IsDebuggerPresent** windows API call will be non-zero. The non-zero return value (1) will be stored in eax.

**test eax, eax ->** Perform bitwise AND operation, so 1 AND 1 is 1. So, ZF will be 0.

**setnz al ->** al is lower value of eax. The setnz will set value if ZF=0. Since ZF=0, al = 1.  

**test al, al ->** Perform bitwise AND operation, so 1 and 1 is 1. So, ZF will be 0.

**jz short loc_1400015A9 ->** Will jump to offset 1400015A9 if ZF=1. Since, ZF=0, it will not take the jump

The program flow will continue towards with red arrow detecting the debugger. And using **MessageBox** windows API, it will print "Oh, you think you're slick, huh? I see your debugger over there. No soup for you!". 

<br>

### Second Case: Without Debugger

When the sample is not being debugged, the return value from **IsDebuggerPresent** windows API call will be zero. The zero return value (0) will be stored in eax.

**test eax, eax ->** Perform bitwise AND operation, so 0 AND 0 is 0. So, ZF will be 1.

**setnz al ->** al is lower value of eax. The setnz will set value if ZF=1. Since ZF=1, al = 0.  

**test al, al ->** Perform bitwise AND operation, so 0 and 0 is 0. So, ZF will be 1.

**jz short loc_1400015A9 ->** Will jump to offset 1400015A9 if ZF=1. Since, ZF=1, it will take the jump

The program flow will continue towards with green arrow. And using **MessageBox** windows API, it will print "No debugger detected! Cowabunga, dudes!". 

<br>

### Defeating Anti-Debugging

The sample was loaded to the x32dbg and breakpoint was added to the **IsDebuggerPresent** API with command below.

`bp IsDebuggerPresent`

In x32dbg, the sample was run with F9 till it reach the breakpoint on **IsDebuggerPresent** API. After it reach that breakpoint, it was then jumped to its return value using Ctrl + F9. Then, the return value of **IsDebuggerPresent**, stored in eax was modified from 1 to 0. 

With this the Anti-Debugging technique using **IsDebuggerPresent** API can be defeated.

<br>

## Detection with YARA Rule:

    rule AntiDebugging{
    meta:
            author= "Venus Chhantel"
            description= "Detecting AntiDebugging Samples"
    strings:
            $antiDebugging_API = "IsDebuggerPresent"
    condition:
            uint16(0) == 0x5A4D and
            (
                    $antiDebugging_API
            )
    }
