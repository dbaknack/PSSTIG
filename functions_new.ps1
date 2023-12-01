
function Get-XMLData($Path,$STIGType){
    switch($STIGType){
        'SQL'{
            [xml]$RawXML = Get-Content -Path '/Users/alexhernandez/LocalRepo/PSSTIG/Sources/U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG/U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml' -Raw
            $Group = @()
            $Group += $RawXML.Benchmark.Group | ForEach-Object {
                [pscustomobject]@{
                    CP_PrimaryKey = ($_.id) -replace ("V-",'')
                    ID = $_.id
                    Title = $_.title
                    Description = $_.description
                    #Rule = $_.rule
                }
            }
        
            $Rule = @()
            $Rule += $RawXML.Benchmark.Group.Rule | ForEach-Object {
                [pscustomobject]@{
                    CP_PrimaryKey = ($_.id).Substring(3,6)
                    ID = $_.id
                    Weight = $_.weight
                    Severity = $_.severity
                    Version = $_.version
                    Title = $_.title
                    Description = $_.description
                    Reference = $_.reference
                    Ident = $_.ident
                    FixText = $_.fixtext
                    Check = $_.check
                }
            }
        
            $TagTable = [ordered]@{
                VulnDiscussion = @{pattern = '(<VulnDiscussion>)(.*)(</VulnDiscussion>)'}
                FalsePositives = @{pattern = '(<FalsePositives>)(.*)(</FalsePositives>)'}
                FalseNegatives = @{pattern = '(<FalseNegatives>)(.*)(</FalseNegatives>)'}
                Documentable = @{pattern = '(<Documentable>)(.*)(</Documentable>)'}
                Mitigations = @{pattern = '(<Mitigations>)(.*)(</Mitigations>)'}
                SeverityOverrideGuidance = @{pattern = '(<SeverityOverrideGuidance>)(.*)(</SeverityOverrideGuidance>)'}
                PotentialImpacts = @{pattern = '(<PotentialImpacts>)(.*)(</PotentialImpacts>)'}
                ThirdPartyTools = @{pattern = '(<ThirdPartyTools>)(.*)(</ThirdPartyTools>)'}
                MitigationControl = @{pattern = '(<MitigationControl>)(.*)(</MitigationControl>)'}
                Responsibility = @{pattern = '(<Responsibility>)(.*)(</Responsibility>)'}
                IAControls = @{pattern = '(<IAControls>)(.*)(</IAControls>)'}
            }
            $Rule | ForEach-Object{
                $DescriptionList = @()
                ($_.Description) -split (" ") | ForEach-Object{
                    $DescriptionList += $_ -replace ("\n","")
                }
            
                $DescriptionString = $DescriptionList -join " "
                $DescriptionTable = [ordered]@{}
                foreach($tag in $TagTable.Keys){
                    if($DescriptionString -match $TagTable.$tag.pattern){
                        $DescriptionTable.Add($tag,$Matches[2])
                    }
                }
                $Description = New-Object PSObject -Property $DescriptionTable
                $_ | Add-Member -MemberType NoteProperty -Name "New_Description" -Value $Description
            }
            
            $Check = @()
            $Check += $RawXML.Benchmark.Group.Rule.Check | ForEach-Object {
                [pscustomobject]@{
                    System = $_.system
                    CheckContentRef = $_.'check-content-ref'
                    CheckContent = $_.'check-content'
                }
            }
            
            foreach($cc in $Check){
                $New_CheckContent = @()
                ($cc.CheckContent -split ("`n")) | ForEach-Object{
                    if($_.length -ne 0){
                        $New_CheckContent += $_
                    }
                }
                $cc.CheckContent = $New_CheckContent
            }
            $FixText = $RawXML.Benchmark.Group.Rule.fixtext
            foreach($ft in $FixText){
                $New_FixText = @()
                    $ft.'#text' -split ("`n") | ForEach-Object{
                    if($_.length -ne 0){
                        $New_FixText += $_
                    }
                }
                $ft.'#text' = $New_FixText
            }
        }
        default {}
    }
    $MasterObject = @()
    $RuleCounter = 1
    foreach($rulecheckid in $Rule){

        foreach($chk in $Check){
            $LinkedCheckItems = $chk | Select-Object * | Where-Object {$chk.System -eq $rulecheckid.Check.system}
        }

        $LinkedDescriptionItems = $rulecheckid.New_Description | Select-Object -Property *
        #$FilteredRuleProps      = $rulecheckid | Select-Object -Property * -ExcludeProperty ('Description','Check','New_Description','FixText')

        foreach($fix in $FixText){
            $linkedFixItems = $fix | Select-Object 'fixref','#text' | Where-Object {$fix.fixref -eq $rulecheckid.FixText.fixref}
        }
        foreach($grp in $Group){
            $linkedGroupItems = ($Group | Select-Object * | Where-Object {$_.CP_PrimaryKey -eq $rulecheckid.CP_PrimaryKey}) | Select-Object -Property * -ExcludeProperty ('Rule','Description')
        }
        
        $ResolutionDocName = "\ResolutionFor-{0}-{1}-{2}.md" -f $linkedGroupItems.CP_PrimaryKey,(($rulecheckid.Reference.Subject) -replace (" ","_")),$rulecheckid.Reference.Identifier

        $MasterObject += [pscustomobject]@{
            Status                      = 'NA'
            DateTimeLastWorked          = 'Never'
            AdminWorkingVulnerability   = 'Unassgined'
            ResolutionDocName           = $ResolutionDocName
            Comments                    = 'NA'
            AssignedBy                  = 'NA'
            AssginedDateTime            = 'NA'
            TeamWorkingThis             = 'NA'
            CheckedOut                  = 0
            DifficultyRating            = 0
            STIGNum                     = $RuleCounter
            VID                         = $linkedGroupItems.CP_PrimaryKey
            ID                          = $linkedGroupItems.ID
            GrpTitle                    = $linkedGroupItems.Title
            RuleID                      = $rulecheckid.ID
            Weight                      = $rulecheckid.Weight
            Seveirty                    = $rulecheckid.Severity
            Version                     = $rulecheckid.Version
            RuleTitle                   = $rulecheckid.Title
            STIGTitle                   = $rulecheckid.Reference.Title
            Publisher                   = $rulecheckid.Reference.Publisher
            Type                        = $rulecheckid.Reference.Type
            Subject                     = $rulecheckid.Reference.Subject
            Identifier                  = $rulecheckid.Reference.Identifier
            FalsePositive               = $LinkedDescriptionItems.FalsePositive
            FalseNegative               = $LinkedDescriptionItems.FalseNegative
            Documentable                = $LinkedDescriptionItems.Documentable
            Mitigations                 = $LinkedDescriptionItems.Mitigations
            SeverityOverrideGuidance    = $LinkedDescriptionItems.$SeverityOverrideGuidance
            ThirdPartyTools             = $LinkedDescriptionItems.ThirdPartyTools
            MitigationControl           = $LinkedDescriptionItems.MitigationControl
            Responsability              = $LinkedDescriptionItems.Responsability
            IAControls                  = $LinkedDescriptionItems.IAControls
            System                      = $LinkedCheckItems.System
            CheckContent                = $LinkedCheckItems.CheckContent
            FixRef                      = $linkedFixItems.fixref
            FixTextFilePath             = $linkedFixItems.'#text'
        }
        $RuleCounter = $RuleCounter + 1
    }
    $MasterObject
}

$GetXMLDataParams = @{
    Path        = ".\sources\U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml"
    STIGType    = "SQL"
}
$MyData = (Get-XMLData @GetXMLDataParams) 
$MyData | Export-Csv -Path  ./tests2.csv -Delimiter "," 
