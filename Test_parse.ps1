function Read-MyXML([string]$XMLFilePath){
    [xml]$MyXMLContent = Get-Content -path ./database_xml.xml
    $NameSpace = New-Object System.Xml.XmlNamespaceManager($MyXMLContent.NameTable)
    $NameSpace.AddNamespace("ns", "http://checklists.nist.gov/xccdf/1.1") 
    $MyXMLContent
}

$MyXMLContent = Read-MyXML -XMLFilePath ".\test.xml" 
function Get-Groups([psobject]$XMLContent){
    $MainData = $MyXMLContent.SelectNodes("//ns:Group", $namespace)
    $MainData
}

$GroupsList = (Get-Groups -XMLContent $MyXMLContent)
$Main_ReferenceTable = [ordered]@{

    # custom properties
    STIG_InternalID             = [int]
    CheckedBy_AdminName         = [string]
    Checked_DateTime_MT         = [string]
    STIG_Resolved               = [string]

    Documentation               = [string]
    Scheduled_To_Resolve        = [string]
    DateTime_Scheduled_MT       = [string]
    Resolution_Approved         = [string]
    Approved_By                 = [string]
    Resolved_By                 = [string]

    # from xml document
    FindingID                   = [string]
    Severity                    = [string]
    Weight                      = [int]
    Rule_id                     = [string]
    Reference_Title             = [string]
    Reference_Publisher         = [string]
    Reference_Subject           = [string]
    Reference_Identifier        = [int]

    Fix_ID                      = [string]
    Fix_Text                    = [string]
    Check_System                = [string]
    Check_Text                  = [string]

    VulnDiscussion            = [string]
    False_Positive              = [string]
    False_Negative              = [string]
    Documentable                = [string]
    Mitigations                 = [string]
    Severity_Override_Guidance  = [string]
    Potential_Impacts           = [string]
    Third_Party_Tools           = [string]
    Mitigation_Control          = [string]
    Responsibility              = [string]
    IA_Controls                 = [string]
}

$SIID = 1
foreach($group in $GroupsList){
    $Main_ReferenceTable.STIG_InternalID = $SIID
    $Main_ReferenceTable.CheckedBy_AdminName = 'N/A'
    $Main_ReferenceTable.Checked_DateTime_MT = 'N/A'
    $Main_ReferenceTable.STIG_Resolved = 'false'

    $Documentation_FileName = "{0}_{1}_{2}_{3}.md" -f
        $group.Rule.reference.publisher,
        $group.Rule.reference.subject,
        $group.Rule.reference.identifier,
        $group.Rule.fixtext.GetAttribute('fixref')
    $Main_ReferenceTable.Documentation = "c:\user\abrah.hernandez\Documents\Knowledge_Base\SOP_Library\Drafts\$($Documentation_FileName)"
    $Main_ReferenceTable.Scheduled_To_Resolve = 'false'
    $Main_ReferenceTable.DateTime_Scheduled_MT = "N/A"
    $Main_ReferenceTable.Resolution_Approved = 'false'
    $Main_ReferenceTable.Approved_By = "N/A"
    $Main_ReferenceTable.Resolved_By = "N/A"

    $Main_ReferenceTable.FindingID = $group.GetAttribute("id").Replace("V-","")

    # rule
    $Main_ReferenceTable.Severity = $group.Rule.GetAttribute("severity").ToUpper()
    $Main_ReferenceTable.Weight =  ([math]::round(($group.Rule.GetAttribute("weight")),2))
    $Main_ReferenceTable.Rule_ID = $group.Rule.GetAttribute("id")
    
    # references
    $Main_ReferenceTable.Reference_Title =  $group.Rule.reference.title
    $Main_ReferenceTable.Reference_Publisher =  $group.Rule.reference.publisher
    $Main_ReferenceTable.Reference_Subject =  $group.Rule.reference.subject
    $Main_ReferenceTable.Reference_Identifier =  $group.Rule.reference.identifier

    # ident
    $Main_ReferenceTable.Fix_ID =  $group.Rule.fixtext.GetAttribute('fixref')
    $Main_ReferenceTable.Fix_Text =  $group.Rule.fixtext.'#text'
    $Main_ReferenceTable.Check_System =  $group.Rule.check.system
    $Main_ReferenceTable.Check_Text = $group.Rule.check.'check-content'
    switch($group.Rule.description){
        # vulnerability discussion
        {[regex]::Match(($group.Rule.description), '<VulnDiscussion>[\s\S]+</VulnDiscussion>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<VulnDiscussion>[\s\S]+</VulnDiscussion>').Value) 
            $modifiedText = $inputText -replace '\s+',' '
            $modifiedText = $modifiedText -replace ('<VulnDiscussion>','')
            $modifiedText = $modifiedText -replace ('</VulnDiscussion>','')
            $VulnDiscussion = $modifiedText
            $Main_ReferenceTable.VulnDiscussion = $VulnDiscussion
        }
        # false positive
        {[regex]::Match(($group.Rule.description), '<FalsePositives>[\s\S]+</FalsePositives>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<FalsePositives>[\s\S]+</FalsePositives>').Value) 
            $modifiedText = $inputText -replace ('<FalsePositives>[\s\S]+</FalsePositives>','N/A')
            $FalsePositives = $modifiedText
            $Main_ReferenceTable.False_Positive = $FalsePositives
        }
        # false negative
        {[regex]::Match(($group.Rule.description), '<FalseNegatives>[\s\S]+</FalseNegatives>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<FalseNegatives>[\s\S]+</FalseNegatives>').Value) 
            $modifiedText = $inputText -replace ('<FalseNegatives>[\s\S]+</FalseNegatives>','N/A')
            $FalseNegatives = $modifiedText
            $Main_ReferenceTable.False_Negative = $FalseNegatives
        }
        # documentable
        {[regex]::Match(($group.Rule.description), '<Documentable>[\s\S]+</Documentable>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<Documentable>[\s\S]+</Documentable>').Value) 
            $modifiedText = $inputText -replace ('<Documentable>[\s\S]+</Documentable>','N/A')
            $Documentable = $modifiedText
            $Main_ReferenceTable.Documentable = $Documentable
        }
        # mitigations
        {[regex]::Match(($group.Rule.description), '<Mitigations>[\s\S]+</Mitigations>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<Mitigations>[\s\S]+</Mitigations>').Value) 
            $modifiedText = $inputText -replace ('<Mitigations>[\s\S]+</Mitigations>','N/A')
            $Mitigations = $modifiedText
            $Main_ReferenceTable.Mitigations = $Mitigations
        }
        # severity override guidance
        {[regex]::Match(($group.Rule.description), '<SeverityOverrideGuidance>[\s\S]+</SeverityOverrideGuidance>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<SeverityOverrideGuidance>[\s\S]+</SeverityOverrideGuidance>').Value) 
            $modifiedText = $inputText -replace ('<SeverityOverrideGuidance>[\s\S]+</SeverityOverrideGuidance>','N/A')
            $SeverityOverrideGuidance = $modifiedText
            $Main_ReferenceTable.Severity_Override_Guidance = $SeverityOverrideGuidance
        }
        # potential impact
        {[regex]::Match(($group.Rule.description), '<PotentialImpacts>[\s\S]+</PotentialImpacts>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<PotentialImpacts>[\s\S]+</PotentialImpacts>').Value) 
            $modifiedText = $inputText -replace ('<PotentialImpacts>[\s\S]+</PotentialImpacts>','N/A')
            $PotentialImpacts = $modifiedText
            $Main_ReferenceTable.Potential_Impacts = $PotentialImpacts
        }
        # third party tools
        {[regex]::Match(($group.Rule.description), '<ThirdPartyTools>[\s\S]+</ThirdPartyTools>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<ThirdPartyTools>[\s\S]+</ThirdPartyTools>').Value) 
            $modifiedText = $inputText -replace ('<ThirdPartyTools>[\s\S]+</ThirdPartyTools>','N/A')
            $ThirdPartyTools = $modifiedText
            $Main_ReferenceTable.Third_Party_Tools = $ThirdPartyTools
        }
        # mitigation controls
        {[regex]::Match(($group.Rule.description), '<MitigationControl>[\s\S]+</MitigationControl>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<MitigationControl>[\s\S]+</MitigationControl>').Value) 
            $modifiedText = $inputText -replace ('<MitigationControl>[\s\S]+</MitigationControl>','N/A')
            $MitigationControl = $modifiedText
            $Main_ReferenceTable.Mitigation_Control = $MitigationControl
        }
        # resposibility
        {[regex]::Match(($group.Rule.description), '<Responsibility>[\s\S]+</Responsibility>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<Responsibility>[\s\S]+</Responsibility>').Value) 
            $modifiedText = $inputText -replace ('<Responsibility>[\s\S]+</Responsibility>','N/A')
            $Responsibility = $modifiedText
            $Main_ReferenceTable.Responsibility = $Responsibility
        }
        # IAControls
        {[regex]::Match(($group.Rule.description), '<IAControls>[\s\S]+</IAControls>')}{
            $inputText = ([regex]::Match(($group.Rule.description), '<IAControls>[\s\S]+</IAControls>').Value) 
            $modifiedText = $inputText -replace ('<IAControls>[\s\S]+</IAControls>','N/A')
            $IAControls = $modifiedText
            $Main_ReferenceTable.IA_Controls = $IAControls
        }
    }
    $SIID = $SIID + 1

    $row_count = 33
    $row = @()
    foreach($Entry in $Main_ReferenceTable.keys){
        $row += "'$($Main_ReferenceTable.$Entry)'"
    }

    }
}




$namespaceManager = New-Object System.Xml.XmlNamespaceManager($MyXMLContent.NameTable)
$nodes = $MyXMLContent.SelectNodes("//ns:ElementName", $namespaceManager)

$namespaceManager = New-Object System.Xml.XmlNamespaceManager($MyXMLContent.NameTable)


$GroupsList = (Get-Groups -XMLContent $MyXMLContent)

$GroupsList.Rule.check.'check-content'[0]

$RawXML = Get-Content -path .\database_xml.xml


$string = ($GroupsList.Rule.check.'check-content'[24])

foreach($string in $GroupsList.Rule.check.'check-content'){
# split into words
$words = $string.split(' ')
$new_words = @()
foreach($word in $words){
   $letters = $word.toCharArray()
   $newletters = @()
    foreach($letter in $letters){
        if(($letter -match "\n")){
            #write-host 'empty char' -ForegroundColor Red
        }else{
            $newletters += $letter
        }
    }
    $new_words += $newletters -join ''
}
write-host "`n ---------------------------------------"
#$new_words -join ' '
"`n ---------------------------------------"+$string | Out-File -FilePath .\checkText.txt -Append
}


