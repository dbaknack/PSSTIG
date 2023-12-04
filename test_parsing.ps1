Class PSSTIG2{
    # class properties, relavent to the enviornment you're running in
    $Enviornmental = @{
        Settings = @{
            OS          = [System.Environment]::OSVersion.Platform
            Separator   = Invoke-Command -ScriptBlock{
                $use = switch([System.Environment]::OSVersion.Platform){
                    'unix'      {'/'}
                    'Win32NT'   {'\'}
                    default     {
                        $error_msg = '[{0}]:: {1}' -f'PSStig','unable to figure out what operating system your using.'
                        Write-Error -Message $error_msg -Category 'InvalidResult'
                    }
                }
                $use
            }

            PSStig = @{
                paths = @{
                    root    = @{ is_valid = [bool] ; use = [Environment]::GetFolderPath('MyDocuments') }
                    custom  = @{ is_valid = [bool] ; use = [string] }
                }
            }

            StigViewer = @{
                paths = @{
                    root    = @{ is_valid = [bool] ; use = [Environment]::GetFolderPath('MyDocuments') }
                    custom  = @{ is_valid = [bool] ; use = [string] }
                }
            }
        }
    }    
    # source table store tags to path locations
    $OperationalPathsTable = @{
        PSSTIGDATA = @{
            Root        = @{
                default = @{
                    is_valid    = [bool]
                    path        = [Environment]::GetFolderPath('MyDocuments')
                }
                custom  = @{
                    is_valid    = [bool]
                    path        = [string]
                }
            }

            STIGDATA            = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\PSSTIGDATA"
            Archive             = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\PSSTIGDATA\{0}\{1}\Archive"
            Backups             = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\PSSTIGDATA\{0}\{1}\Backups"
            ReferenceDocuments  = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\PSSTIGDATA\{0}\{1}\ReferenceDocuments"
        }

        # psstigviewer paths are used to read data from sources shared by the stig-viewer tool
        STIGVIEWERDATA = @{
            STIGDATA    = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\STIGVIEWERDATA\"
        }

        # hostdata paths are paths to list of windows servers or sql server instances
        HOSTDATA = @{
            HOSTFiles   = "$([Environment]::GetFolderPath('MyDocuments'))\Knowledge_Base\Sources_Library\HOSTDATA\"
        }
    }

    $Source = @{
        HostsFiles      = Get-ChildItem -Path $this.GetPathsFromSourceTable('HOSTDATA','HOSTFiles')
        PSSTIGS         = Get-ChildItem -Path $this.GetPathsFromSourceTable('PSSTIGDATA','STIGDATA')
        STIGVIEWERDATA  = Get-ChildItem -Path $this.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA')
    }

    PSSTIG2([hashtable]$PathsConfiguration){
        # alot depends on proper settings begin provided, so while this method
        # is overly verbose, it's best to know if there is issues right off the bat

        $paths_keys_list    = @('use_defaults','psstig_root', 'stigviewer_root')
        $missing_keys       = $paths_keys_list | Where-Object { -not $PathsConfiguration.ContainsKey($_) }

        # exit condition will be raised if the proper parameters
        # are not provided

        if($missing_keys.count -gt 0){ $exit_condition_raised = $true }
        else{ $exit_condition_raised = $false }

        if($exit_condition_raised -eq $false){

            # in this portion we are evaluating the default preference set
            switch($PathsConfiguration.use_defaults){
                $true{
                    # if true, then by default the module with use the documents folder on your system
                    $this.Enviornmental.Settings.PSStig.paths.root.use      = [Environment]::GetFolderPath('MyDocuments')
                    $this.Enviornmental.Settings.StigViewer.paths.root.use  = [Environment]::GetFolderPath('MyDocuments')
                }

                $false{
                    # if false, then the user provided values will be used,
                    # a check will be done to make sure they're not empty
                    if($PathsConfiguration.psstig_root.length -eq 0){ $exit_condition_raised = $true }
                    if($PathsConfiguration.psstig_root.length -eq 0){ $exit_condition_raised = $true }

                    # the exit condition will still be false if no error
                    # was seen up to this point
                    if($exit_condition_raised -eq $false){
                        $this.Enviornmental.Settings.PSStig.paths.root.use      = $PathsConfiguration.psstig_root
                        $this.Enviornmental.Settings.StigViewer.paths.root.use  = $PathsConfiguration.stigviewer_root
                    }
                }
                default{
                    # you could still provide nothing for the parameter 'use_default'
                    # we can handle that here, in the default case section
                    $exit_condition_raised = $true
                }
            }

            # up to now, input fail conditions have been handled
            # but we do want to make sure the paths set are reachable
            if( [System.IO.Path]::Exists($this.Enviornmental.Settings.PSStig.paths.root.use) ) {
                $this.Enviornmental.Settings.PSStig.paths.root.is_valid = $true }
            else{ 
                $exit_condition_raised = $true
                $this.Enviornmental.Settings.PSStig.paths.root.is_valid = $false }

            if( [System.IO.Path]::Exists($this.Enviornmental.Settings.StigViewer.paths.root.use) ) {
                $this.Enviornmental.Settings.StigViewer.paths.root.is_valid = $true }
            else{
                $exit_condition_raised = $true
                $this.Enviornmental.Settings.StigViewer.paths.root.is_valid = $false}

            
            # it would be fair to assume that, if you went to the trouble of making a module
            # and the user went through the trouble of downloading it, that there should be
            # an option for the user to have a chance to provide paths that work in the event
            # that the paths didnt work on the first go
            if($exit_condition_raised -eq $true){
                $GIVEUP     = $false
                $reprompted = $false
                $input_value = [string]
                do{
                    # assuming both paths are wrong, the message should explictly make mention of that
                    if(($this.Enviornmental.Settings.PSStig.paths.root.is_valid) -and ($this.Enviornmental.Settings.StigViewer.paths.root.is_valid)){
                        $reprompted = $true
                        $input_msg = "{0} {1}" -f
                        "Looks like both of the paths you provide are not reachable, if you would like to provide alternate paths"
                        "you can do so by typing them now or type 'end' to quite all together..."
                         Write-Host -Object $input_msg --ForegroundColor 'yellow'

                        # a for loop can promp for each of the condition we want to ask the user
                        # to resupply
                        for ($i = 0; $i -le 1; $i++) {
                            if($i -eq 0){
                                $input_msg = "{0}" -f "'stig_viewer fullpath' or 'end', press any key to continue"
                                Write-Verbose -Message $input_msg -ForegroundColor 'yellow'
                                $input_value = Read-Host -Prompt
                                $this.Enviornmental.Settings.StigViewer.paths.root.use  = $input_value
                            }

                            if($input_value -eq "end"){
                                $GIVEUP = $true
                            }

                            if($GIVEUP -eq $false){
                                if($i -eq 1){
                                    $input_msg = "{0}" -f "'psstig fullpath' or 'end', press any key to continue"
                                    Write-Verbose -Message $input_msg -ForegroundColor 'yellow'
                                    $this.Enviornmental.Settings.PSStig.paths.root.use = $input_value
                                }
                            }
                            if($input_value -eq "end"){
                                $GIVEUP -eq $true
                            }
                        }
                    }

                    # dont prompt again if the first condition to prompt was met
                    if($reprompted -eq $false){
                        $input_msg = "{0} {1}" -f
                        "Looks like one of the paths you provide is not reachable, if you would like to provide alternate path"
                        "you can do so by typing it now or type 'end' to quite all together..."
                        Write-Host -Object $input_msg --ForegroundColor 'yellow'

                        # in the event that only one of the two was incorrect,
                        if(($this.Enviornmental.Settings.PSStig.paths.root.is_valid) -or ($this.Enviornmental.Settings.StigViewer.paths.root.is_valid)){
                            if(-not($this.Enviornmental.Settings.PSStig.paths.root.is_valid)){
                                $input_msg = "{0}" -f "'psstig fullpath' or 'end', press any key to continue"
                                Write-Verbose -Message $input_msg -ForegroundColor 'yellow'
                                $input_value = Read-Host -Prompt

                                if($input_value -ne "end"){
                                    $this.Enviornmental.Settings.PSStig.paths.root.use = $input_value
                                }
                            }
                            if(-not($this.Enviornmental.Settings.StigViewer.paths.root.is_valid)){
                                $input_msg = "{0}" -f "'stig_viewer fullpath' or 'end', press any key to continue"
                                Write-Verbose -Message $input_msg -ForegroundColor 'yellow'
                                $input_value = Read-Host -Prompt

                                if($input_value -ne "end"){
                                    $this.Enviornmental.Settings.StigViewer.paths.root.use  = $input_value
                                }
                            }
                            if($input_value -eq "end"){
                                $GIVEUP = $true
                            }
                        }
                        $reprompted = $false
                    }

                # only way you can exit this loop is if the user either quites setup with 'end' or
                # if both the paths to set are valid
                }until(($GIVEUP -eq $true) -or (($this.Enviornmental.Settings.PSStig.paths.root.is_valid) -and ($this.Enviornmental.Settings.StigViewer.paths.root.is_valid)))
                
                if(($GIVEUP -eq $false) -or (($this.Enviornmental.Settings.PSStig.paths.root.is_valid -eq $true) -and ($this.Enviornmental.Settings.StigViewer.paths.root.is_valid -eq $true))){
                    $setupComplete = $true
                }else{
                    $setupComplete = $false
                }
            }
            $setupComplete = $true
        }
        # nothing here happens
    }

    # use this when you need to do an operation that 
    [psobject]GetPathsFromSourceTable([string]$SourceKey,[string]$SourceRef){
        $mySource       = $this.OperationalPathsTable
        $mySubSource    = $mySource[$SourceKey]
       return $mySubSource[$SourceRef]
    }

    # getter from source properties
    [psobject]GetPathItems([string]$Source){
        $itemsfrom = $null
        switch($Source){
            'HostsFiles'{
                $itemsfrom = Get-ChildItem -Path $this.GetPathsFromSourceTable('HOSTDATA','HOSTFiles')
            }
            'PSSTIGDATA'{
                $itemsfrom = Get-ChildItem -Path $this.GetPathsFromSourceTable('PSSTIGDATA','STIGDATA')
            }
            'STIGVIEWERDATA'{
                $itemsfrom = Get-ChildItem -Path $this.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA')
            }
            default {
                Write-host "[GetPathItems]::the provided source '$($Source)' is not mapped to a SourceTable object" -ForegroundColor Red
                $itemsfrom = $false
            }
        }
        return $itemsfrom
    }

    # this works when source is a tag to a folder, and filename is a file in that folder
    [psobject]GetItemData([string]$Source,[string]$FileName){
        $MySourceOject = $this.GetPathItems($Source)
        $MySelectedSourceFile = $MySourceOject | Select-Object -Property * | Where-Object {$_.name -match $FileName}

        $MyData = $null
        $MyItemType = $MySelectedSourceFile.Attributes
        switch ($MyItemType) {
            'Archive' {
                switch($MySelectedSourceFile.extension){
                    '.csv'{
                        [pscustomobject]$MyData = Get-Content -Path ($MySelectedSourceFile).FullName

                    }
                    '.xml'{
                        [xml]$MyData = Get-Content -Path ($MySelectedSourceFile).FullName
                    }
                    '.md'{
                        $MyData = Get-Content -Path ($MySelectedSourceFile).FullName -raw
                    }
                    '.txt'{
                        $MyData = Get-Content -Path ($MySelectedSourceFile).FullName -raw
                    }
                    default{
                        Write-Host "[GetItemData]:: getting data from filetype  '$($MySelectedSourceFile.extension)' is not of a filetype matched" -ForegroundColor Red
                    }
                }
               
            }
            default {
                Write-Host "[GetItemData]:: the provide itemtype '$($MySelectedSourceFile.name)' is not of a type matched" -ForegroundColor Red
                return $MyItemType
                $MyData = $false
            }
        }
        return $MyData
    }

    # this works when source is a tag to a folder, and file name
    # this needs to be your source $test.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA')
    [psobject]GetItemDataFromFolder([string]$MySourcePath,[string]$FolderName,[string]$FileName){
        $MySourceFiles = Get-ChildItem -Path "$($MySourcePath)$($FolderName)"
        $MySelectedSourceFile = $MySourceFiles  | Select-Object -Property * | Where-Object {$_.Name -match $FileName}

        $MyData = $null
        $MyItemType = $MySelectedSourceFile.Attributes
        switch ($MyItemType) {
            'Archive' {
                switch($MySelectedSourceFile.extension){
                    '.csv'{
                        [pscustomobject]$MyData = Get-Content -Path ($MySelectedSourceFile).FullName

                    }
                    '.xml'{
                        [xml]$MyData = Get-Content -Path ($MySelectedSourceFile).FullName
                    }
                    '.md'{
                        $MyData = Get-Content -Path ($MySelectedSourceFile).FullName -raw
                    }
                    '.txt'{
                        $MyData = Get-Content -Path ($MySelectedSourceFile).FullName -raw
                    }
                    default{
                        Write-Host "[GetItemDataFromFolder]:: getting data from filetype  '$($MySelectedSourceFile.extension)' is not of a filetype matched" -ForegroundColor Red
                    }
                }
               
            }
            default {
                Write-Host "[GetItemDataFromFolder]:: the provide itemtype '$($MySelectedSourceFile.name)' is not of a type matched" -ForegroundColor Red
                return $MyItemType
                $MyData = $false
            }
        }
        return $MyData
    }

    # given a stigviewer folder, get the files in that location
    [psobject]GetSTIGVIEWERXMLS([string]$STIGVIEWERFolder){
        $NoFolder = [bool]
        $MyFiles = @()
        $STIGVIEWERFolders = $this.GetPathItems('STIGVIEWERDATA')
        $MySTIGVIEWERFolderSELECTED = $STIGVIEWERFolders | Select-Object -Property * | Where-Object {$_.name -match $STIGVIEWERFOLDER}
        if($MySTIGVIEWERFolderSELECTED.count -eq 0){
            Write-Host "[GetSTIGVIEWERXMLS]:: there is no folder named '$($STIGVIEWERFolder)' in '$($this.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA'))'" -ForegroundColor Red
            $NoFolder = $true
        }else{
            $NoFolder = $false
        }
        if($NoFolder -eq $false){
            if(Test-Path -path ($MySTIGVIEWERFolderSELECTED).FullName){
                $MyFiles = Get-ChildItem -Path $MySTIGVIEWERFolderSELECTED.FullName
            }else{
                Write-Host "[GetSTIGVIEWERXMLS]:: the source directory provided for STIGVIEWER source of xml files does not exits" -ForegroundColor Red
                $MyFiles = $false
            }
        }
        return $MyFiles
    }

    # this works the same as 'GetSTIGVIEWERXMLS' its just for PSSTIGDATA tho, its better to make that distintion
    [psobject]GetPSSTIGDATA([string]$PSSTIGFolder){
        $NoFolder = [bool]
        $MyFiles = @()
        $PSSTIGFolders = $this.GetPathItems('PSSTIGDATA')
        $MyPSSTIGFolderFolderSELECTED = $PSSTIGFolders | Select-Object -Property * | Where-Object {$_.name -match $PSSTIGFolder}
        if($MyPSSTIGFolderFolderSELECTED.count -eq 0){
            Write-Host "[GetSTIGVIEWERXMLS]:: there is no folder named '$($PSSTIGFolder)' in '$($this.GetPathsFromSourceTable('PSSTIGDATA','STIGDATA'))'" -ForegroundColor Red
            $NoFolder = $true
        }else{
            $NoFolder = $false
        }
        if($NoFolder -eq $false){
            if(Test-Path -path ($MyPSSTIGFolderFolderSELECTED).FullName){
                $MyFiles = Get-ChildItem -Path $MyPSSTIGFolderFolderSELECTED.FullName
            }else{
                Write-Host "[GetPSSTIGDATA]:: the source directory provided for PSSTIGDATA source of folders does not exits" -ForegroundColor Red
                $MyFiles = $false
            }
        }
        return $MyFiles
    }

    [psobject]ConvertSTIGXMLDATATO([hashtable]$FromSender){
        $MasterObject = @()
        switch($FromSender.STIGType){
            'SQL'{
                switch($FromSender.Format){
                    'csv'{
                        $RawXML = $FromSender.XMLContent
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

                        # this is the pattern table used to parse out the xml to do the conversion
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
                        $New_FixTextObject = @()
                        foreach($ft in $FixText){
                            $New_FixText = @()
                            $textlist = $ft.'#text' -split ("`n") 
                            foreach($text in $textlist){
                                if($text.length -ne 0){
                                    $New_FixText += $text
                                }
                            }

                            $New_FixTextObject += [pscustomobject]@{
                              fixref = $ft.fixref
                              text = $New_FixText  
                            }
                        }
                        #$ft['#text'] = $New_FixText
                        $MasterObject = @()
                        $RuleCounter = 1
                        foreach($rulecheckid in $Rule){

                            $LinkedCheckItems = @()
                            foreach($chk in $Check){
                                $LinkedCheckItems = $chk | Select-Object * | Where-Object { $chk.System -eq $rulecheckid.Check.system }
                            }
                       
                            $LinkedDescriptionItems = $rulecheckid.New_Description | Select-Object -Property *
                            #$FilteredRuleProps      = $rulecheckid | Select-Object -Property * -ExcludeProperty ('Description','Check','New_Description','FixText')
                       
                            $linkedFixItems = @()
                            foreach($fix in $New_FixTextObject){
                                $linkedFixItems = $fix | Select-Object 'fixref','text' | Where-Object {$fix.fixref -eq $rulecheckid.FixText.fixref}
                            }

                            $linkedGroupItems  = @()
                            foreach($grp in $Group){
                                $linkedGroupItems = ($Group | Select-Object * | Where-Object {$_.CP_PrimaryKey -eq $rulecheckid.CP_PrimaryKey}) | Select-Object -Property * -ExcludeProperty ('Rule','Description')
                            }

                            $ResolutionDocName      = ".\ReferenceDocuments\{0}\ResolutionDocument.md" -f $linkedGroupItems.CP_PrimaryKey
                            $FixTextFilePath        = ".\ReferenceDocuments\{0}\FixTextDocs\{1}.txt" -f $linkedGroupItems.CP_PrimaryKey,$linkedFixItems.fixref
                            $CheckContentFilePath   = ".\ReferenceDocuments\{0}\CheckTextDocs\{1}.txt" -f $linkedGroupItems.CP_PrimaryKey,$LinkedCheckItems.system

                            $MasterObject += [pscustomobject]@{
                                STIGNum                     = $RuleCounter
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
                                SeverityOverrideGuidance    = $LinkedDescriptionItems.SeverityOverrideGuidance
                                ThirdPartyTools             = $LinkedDescriptionItems.ThirdPartyTools
                                MitigationControl           = $LinkedDescriptionItems.MitigationControl
                                Responsability              = $LinkedDescriptionItems.Responsability
                                IAControls                  = $LinkedDescriptionItems.IAControls
                                System                      = $LinkedCheckItems.System
                                CheckContent                = $LinkedCheckItems.CheckContent
                                CheckContentFilePath        = $CheckContentFilePath
                                FixRef                      = $linkedFixItems.fixref
                                FixText                     = $linkedFixItems.text
                                FixTextFilePath             = $FixTextFilePath
                            }
                            $RuleCounter = $RuleCounter + 1
                        }
                        $MasterObject
                    }
                    default {
                        Write-Host "[ConvertSTIGXMLDATATO]:: currently can convert to csv... sorry" -ForegroundColor Red
                        return $false      
                    }
                }
                $MasterObject
            }
            default {
                Write-Host "[ConvertSTIGXMLDATATO]:: currently can only do sql related stigs... sorry" -ForegroundColor Red
                return $false
            }
        }
        return $MasterObject
    }
    [void]OutPutConveredData([hashtable]$OutPutDataParamsTable){
        $folderinSTIGDataCreated = $true
        if(-not(Test-Path -Path $OutPutDataParamsTable.PSSTIGDATAFolder.FullName)){
            New-Item -Path $OutPutDataParamsTable.PSSTIGDATAFolder.FullName -ItemType 'Directory'
        }else{
            $folderinSTIGDataCreated = $false
        }

        $FoldersTable = [ordered]@{
            MasterArchivePath           = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\Archive"
            MasterBackupPath            = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\Backups"
            MasterRefDocsPath           = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments"
            MasterFindingDocsPath       = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}"
            MasterFixTextDocsPath       = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\FixTextDocs"
            MasterCheckTextDocsPath     = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\CheckTextDocs"
        }
        $Files = [ordered]@{
            MasterContentDoc        = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\Master.csv"
            MasterRemediationDoc    = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\RemediationDocument.md"
            MasterFixTextDoc        = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\FixTextDocs\{1}.txt"
            MasterCheckTextDoc      = "$(($OutPutDataParamsTable.PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\CheckTextDocs\{1}.txt"
        }
        if($folderinSTIGDataCreated){
            New-Item -path $FoldersTable.MasterArchivePath  -ItemType 'Directory'  
            New-Item -path $FoldersTable.MasterBackupPath   -ItemType 'Directory' 
            New-Item -Path $FoldersTable.MasterRefDocsPath  -ItemType 'Directory' 
       
           
            foreach($STIG in $OutPutDataParamsTable.XMLContent){
                $FindingFolderString = ($FoldersTable.MasterFindingDocsPath -f $STIG.VID)
                if(-not(test-path -Path $FindingFolderString)){
                    New-Item -path  $FindingFolderString  -ItemType 'Directory'
                }
                $RemediationFileString = $Files.MasterRemediationDoc -f $STIG.VID
                if(-not(test-path -Path $RemediationFileString)){
                    New-Item -path  $RemediationFileString -ItemType 'File'

                    # add content to the created containers
                    Set-Content -Path $RemediationFileString
                }
               
                $FixTextFolderString = $FoldersTable.MasterFixTextDocsPath -f $STIG.VID
                if(-not(test-path -Path $FixTextFolderString)){
                    New-Item -path  $FixTextFolderString -ItemType 'Directory'
                }
       
                $FixTextFileString = $Files.MasterFixTextDoc -f $STIG.VID, $STIG.FixRef
                if(-not(test-path -Path $FixTextFileString)){
                    New-Item -path  $FixTextFileString -ItemType 'File'

                    # add content to the created containers
                    Set-Content -Path $FixTextFileString -Value $STIG.FixText
                }
       
                $CheckTextFolderString = $FoldersTable.MasterCheckTextDocsPath -f $STIG.VID
                if(-not(test-path -Path $CheckTextFolderString)){
                    New-Item -path  $CheckTextFolderString -ItemType 'Directory'
                }
                $CHeckTextFileString = $Files.MasterCheckTextDoc -f $STIG.VID, $STIG.System
                if(-not(test-path -Path $CHeckTextFileString)){
                    New-Item -path  $CHeckTextFileString -ItemType 'File'

                    # add content to the created containers
                    Set-Content -Path $CHeckTextFileString -Value $STIG.CheckContent                    
                }
            }
        }
    }
}

$test = [PSSTIG2]::new()

# sources for input will just be your xml content\
$MYXMLContent = $test.GetItemDataFromFolder(
    $test.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA'),
    'U_MS_SQL_Server_2016_Y23M10_STIG',
    'U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf'
)

$OutPutDataParamsTable = @{
    PSSTIGDATAFolder = $test.GetPathItems('PSSTIGDATA')
    XMLContent = $MYXMLContent
}

# output to input
$folderinSTIGDataCreated = $true
$PSSTIGDATAFolder = $test.GetPathItems('PSSTIGDATA')
if(-not(Test-Path -Path $PSSTIGDATAFolder.FullName)){
    New-Item -Path $PSSTIGDATAFolder.FullName -ItemType 'Directory'
}else{
    $folderinSTIGDataCreated = $false
}

$FoldersTable = [ordered]@{
    MasterArchivePath           = "$(($PSSTIGDATAFolder).FullName)\Archive"
    MasterBackupPath            = "$(($PSSTIGDATAFolder).FullName)\Backups"
    MasterRefDocsPath           = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments"
    MasterFindingDocsPath       = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}"
    MasterFixTextDocsPath       = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\FixTextDocs"
    MasterCheckTextDocsPath     = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\CheckTextDocs"
}
$Files = [ordered]@{
    MasterContentDoc        = "$(($PSSTIGDATAFolder).FullName)\Master.csv"
    MasterRemediationDoc    = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\RediationDocument.md"
    MasterFixTextDoc        = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\FixTextDocs\{1}.txt"
    MasterCheckTextDoc      = "$(($PSSTIGDATAFolder).FullName)\ReferenceDocuments\{0}\CheckTextDocs\{1}.txt"
}

if($folderinSTIGDataCreated){
    New-Item -path $FoldersTable.MasterArchivePath  -ItemType 'Directory'  
    New-Item -path $FoldersTable.MasterBackupPath   -ItemType 'Directory' 
    New-Item -Path $FoldersTable.MasterRefDocsPath  -ItemType 'Directory' 

   
    foreach($STIG in $MYConvertedContent){
        $FindingFolderString = ($FoldersTable.MasterFindingDocsPath -f $STIG.VID)
        if(-not(test-path -Path $FindingFolderString)){
            New-Item -path  $FindingFolderString  -ItemType 'Directory'
        }
        $RemediationFileString = $Files.MasterRemediationDoc -f $STIG.VID
        if(-not(test-path -Path $RemediationFileString)){
            New-Item -path  $RemediationFileString -ItemType 'File'
        }
       
        $FixTextFolderString = $FoldersTable.MasterFixTextDocsPath -f $STIG.VID
        if(-not(test-path -Path $FixTextFolderString)){
            New-Item -path  $FixTextFolderString -ItemType 'Directory'
        }

        $FixTextFileString = $Files.MasterFixTextDoc -f $STIG.VID, $STIG.FixRef
        if(-not(test-path -Path $FixTextFileString)){
            New-Item -path  $FixTextFileString -ItemType 'File'
        }

        $CheckTextFolderString = $FoldersTable.MasterCheckTextDocsPath -f $STIG.VID
        if(-not(test-path -Path $CheckTextFolderString)){
            New-Item -path  $CheckTextFolderString -ItemType 'Directory'
        }
        $CHeckTextFileString = $Files.MasterCheckTextDoc -f $STIG.VID, $STIG.System
        if(-not(test-path -Path $CHeckTextFileString)){
            New-Item -path  $CHeckTextFileString -ItemType 'File'
        }
    }
    $MYConvertedContent
}

$MarkDownTemplateTable = @{
    Layout01 = '
    [//]: # (startblock_main_heading)

    {0}
    [//]: # (endblock_main_headings)

    [//]: # (startblock_documentInfo)

    {1}

    [//]: # (endblock_documentInfo)

    [//]: # (startblock_finding)

    {2}

        [//]: # (startblock_findingdetails)

        {3}

        [//]: # (endblock_findingdetails)

    ---

        [//]: # (startblock_CheckText)

        {4}

        [//]: # (endblock_CheckText)

        [//]: # (startblock_FixText)

        {5}

        [//]: # (endblock_FixText)

        [//]: # (startblock_Comments)
       
        {6}

        [//]: # (endblock_Comments)
   
    [//]: # (endblock_findingInfo)
    [//]: # (endblock_finding)

    </br>
    '
    HeadingElement = @{
        main_heading = '# {0} - {1}'
    }
    DocumentInfo = @{
        documentInfo = '
        Publisher:
        ```{0}```
        Type:
            ```{1}```
     
        Subject:
            ```{2}```
     
        Documentation Auther:
            ```{3}```
     
        Date Created:
        ```{4}```
        '
    }
    Finding = @{
        finding =@{
            Heading = '## **Finding - {0}** : {1}'
            Details = '
            FindingID:
            ```{0}```
         
            Severity:
                ```{1}```
           
            Weight:
                ```{2}```
           
            GroupTitle:
                ```{3}```
           
            Status:
                ```{4}```
           
            CheckID:
                ```{5}```
            '
        }
        CheckText = '
            ### Check Description (Per DCSA):
            {0}
        '
        FixText = '
            ### Fix Description (Per DISA):
            {0}
        '
        Comments = '
        ## Comments:
        {0}
        '
    }
}

$ElementsTable = [ordered]@{}
$ElementsTable.Add('Heading',($MarkDownTemplateTable.HeadingElement.main_heading -f $STIG.STIGTitle, $STIG.Identifier))
$ElementsTable.Add('DocumentInfo',
    ($MarkDownTemplateTable.DocumentInfo.documentInfo -f $STIG.Publisher, $STIG.Type, $STIG.Subject, $env:USERNAME, (Get-Date).ToString('yyyy-MM-dd'))
)

foreach($finding in ($MYConvertedContent | Group-Object -Property 'VID')){
    $ElementsTable.Add("-$($finding)",[ordered]@{})
    $ElementsTable."-$($finding)".Add('Heading', $MarkDownTemplateTable.Finding.finding.Heading -f $finding.Group.VID,$finding.Group.RuleTitle)
   
    $ElementsTable."-$($finding)".Add('Details',(
            $MarkDownTemplateTable.Finding.finding.Details -f 
                $finding.Group.VID,
                $finding.Group.Severity,
                $finding.Group.Weight, 
                $finding.Group.GrpTitle, 
                $finding.Group.Status, 
                $finding.Group.System
        )
    )

    # text should always reference the storage location
    $ElementsTable."-$($finding)".Add('CheckText',(
        $MarkDownTemplateTable.Finding.CheckText -f $finding.Group.CheckContent
        )
    )

    $ElementsTable."-$($finding)".Add('CheckText',(
        $MarkDownTemplateTable.Finding.FixText -f $finding.Group.FixText
        )
    )
    $ElementsTable."-$($finding)".Add('CheckText',(
        $MarkDownTemplateTable.Finding.Comments -f $finding.Group.Comments
        )
    )
}

$Stig.FixText | clip.exe
$MYXMLContent = $test.GetItemDataFromFolder(
    $test.GetPathsFromSourceTable('STIGVIEWERDATA','STIGDATA'),
    'U_MS_SQL_Server_2016_Y23M10_STIG',
    'U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf'
)
$MYConvertedContent = $test.ConvertSTIGXMLDATATO(@{
    STIGType    = 'SQL'
    Format      = 'csv'
    XMLContent  = $MYXMLContent
})
$MYConvertedContent | ft -a


























function Get-XMLData($Path,$STIGType){
    switch($STIGType){
        'SQL'{
            [xml]$RawXML = Get-Content -Path $Path
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
            $New_FixTextObject = @()
            foreach($ft in $FixText){
                $New_FixText = @()
                $textlist = $ft.'#text' -split ("`n") 
                foreach($text in $textlist){
                    if($text.length -ne 0){
                        $New_FixText += $text
                    }
                }
   
                $New_FixTextObject += [pscustomobject]@{
                  fixref = $ft.fixref
                  text = $New_FixText  
                }
                #$ft['#text'] = $New_FixText
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

        foreach($fix in $New_FixTextObject){
            $linkedFixItems = $fix | Select-Object 'fixref','text' | Where-Object {$fix.fixref -eq $rulecheckid.FixText.fixref}
        }
        foreach($grp in $Group){
            $linkedGroupItems = ($Group | Select-Object * | Where-Object {$_.CP_PrimaryKey -eq $rulecheckid.CP_PrimaryKey}) | Select-Object -Property * -ExcludeProperty ('Rule','Description')
        }
       
        $ResolutionDocName      = "\ResolutionFor-{0}-{1}-{2}.txt" -f $linkedGroupItems.CP_PrimaryKey,(($rulecheckid.Reference.Subject) -replace (" ","_")),$rulecheckid.Reference.Identifier
        $FixTextFilePath        = "\FixTextFor{0}-{1}-{2}.md" -f $linkedGroupItems.CP_PrimaryKey,(($rulecheckid.Reference.Subject) -replace (" ","_")),$rulecheckid.Reference.Identifier
        $CheckContentFilePath   = "\CheckContentFor{0}-{1}-{2}.txt" -f $linkedGroupItems.CP_PrimaryKey,(($rulecheckid.Reference.Subject) -replace (" ","_")),$rulecheckid.Reference.Identifier


        $MasterObject += [pscustomobject]@{
            STIGNum                     = $RuleCounter
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
            CheckContentFilePath        = $CheckContentFilePath
            FixRef                      = $linkedFixItems.fixref
            FixText                     = $linkedFixItems.text
            FixTextFilePath             = $FixTextFilePath
        }
        $RuleCounter = $RuleCounter + 1
    }
    $MasterObject
}

$GetXMLDataParams = @{
    Path        = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\STIGVIEWERDATA\U_MS_SQL_Server_2016_Y23M10_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml"
    STIGType    = "SQL"
}
$MyData = (Get-XMLData @GetXMLDataParams) 
$MyData
#-------------------------------------------------------------------------------------#
# public functions dervied by class methods and properties are able to be used by user
Function Invoke-PSSTIG{
    $PSSTIG = [PSSTIG]::new()
    $PSSTIG
}

# use this to see the internal references to sources
Function Show-PSSTIGInternalSources{
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.ViewInternalSourceFolders()
}

Function Get-PSSTIGInternalSources([string]$InternalSourceLabel){
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.GetInternalSource($InternalSourceLabel)
}

Function Import-PSSTIGFromInternalSource([string]$InternalSourceLabel){
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.ImportSTIGXMLFolder($InternalSourceLabel)
}
Function Add-PSSTIGSourceReference([string]$SourceLabel,[string]$SourcePath){
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.AddSourceReference($SourceLabel,$SourcePath)
}

Function Show-PSSTIGXMLFile([string]$SourceLabel){
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.GetSTIGXMLFileFromFolder($SourceLabel)
}

Function Import-PSSTIGContent([array]$SourceList){
    #$PSSTIG = Invoke-PSSTIG
    $PSSTIG.GetSTIGXMLContent($SourceList)
}

Function Show-PSSTIGData($FileName,$ViewAs){
    $PSSTIG.ViewXMLData($FileName,$ViewAs)
}
# [void]ExportSTIGsAs([string]$SourceData,[string]$Format,[string]$OutputFolderPath){
Function Export-PSSTIGAs([psobject]$SourceData,[string]$Format,[string]$OutputFolderPath){
    $PSSTIG.ExportSTIGsAs($SourceData,$Format,$OutputFolderPath)
}



C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\HOSTDATA
C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\PSSTIGDATA\U_MS_SQL_Server_2016_Y23M10_STIG
C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\STIGVIEWERDATA

Abe A. Hernandez, Contractor

NORAD | USNORTHCOM |  TEK Systems | Database Administrator

Phone: (719) 554-0831

E-Mail: Abraham.A.Hernandez5.CTR@mail.mil