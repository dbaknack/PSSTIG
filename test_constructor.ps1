Class PSSTIG3{
    $DevSettings = @{
        DEBUG_ON = $true
    }
    $Dynamic = @{
        Settings = @{
            use_defaults    = [bool]
            OS              = [System.Environment]::OSVersion.Platform
            host_name        = [System.Net.Dns]::GetHostName()
            login_name      = Invoke-Command -ScriptBlock{
                $username = whoami
                $username
            }
            Separator   = Invoke-Command -ScriptBlock{
                $use = switch([System.Environment]::OSVersion.Platform){
                    'unix'      {'/'}
                    'Win32NT'   {'\'}
                    default     {'\'}
                }
                $use
            }
        }
    }
    $Enviornmental = @{
        Settings = @{
            SetUpComplete   = $false
            DEBUG_ON        = [bool]
            PSStig          = @{
                paths = @{
                    default = @{ is_valid = $false ; use = [string]}
                    custom  = @{ is_valid = $false ; use = [string] }
                }
            }
            StigViewer      = @{
                paths = @{
                    default = @{ is_valid = $false ; use = [string]}
                    custom  = @{ is_valid = $false ; use = [string]}
                }
            }
        }
    }
    $Cache = @{
        Settings = @{
            Exists  = $false
            Folder  = "$((Get-Location).Path)$($this.Dynamic.Settings.Separator)Cache"
            File    = "$((Get-Location).Path)$($this.Dynamic.Settings.Separator)Cache$($this.Dynamic.Settings.Separator)PSItemCache.json"
        }
    }
    # *--*--*--*--*--*--*--*--*--*--*--* [Utilities] *--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*-- #
    # *--*--*--*--*--*--*--*--*--*--*--* [Utilities] *--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*-- #
    # *--*--*--*--*--*--*--*--*--*--*--* [Initialize] *--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*-- #
    [psobject]XMLParseOut_Discussion([psobject]$RuleDiscussion){
        $TagTable = @{
            VulnDiscussion              = @{pattern = '(<VulnDiscussion>)(.*)(</VulnDiscussion>)'}
            FalsePositives              = @{pattern = '(<FalsePositives>)(.*)(</FalsePositives>)'}
            FalseNegatives              = @{pattern = '(<FalseNegatives>)(.*)(</FalseNegatives>)'}
            Documentable                = @{pattern = '(<Documentable>)(.*)(</Documentable>)'}
            Mitigations                 = @{pattern = '(<Mitigations>)(.*)(</Mitigations>)'}
            SeverityOverrideGuidance    = @{pattern = '(<SeverityOverrideGuidance>)(.*)(</SeverityOverrideGuidance>)'}
            PotentialImpacts            = @{pattern = '(<PotentialImpacts>)(.*)(</PotentialImpacts>)'}
            ThirdPartyTools             = @{pattern = '(<ThirdPartyTools>)(.*)(</ThirdPartyTools>)'}
            MitigationControl           = @{pattern = '(<MitigationControl>)(.*)(</MitigationControl>)'}
            Responsibility              = @{pattern = '(<Responsibility>)(.*)(</Responsibility>)'}
            IAControls                  = @{pattern = '(<IAControls>)(.*)(</IAControls>)'}
        }
        $DiscussionTable = @{}
        $RuleDiscussion | ForEach-Object{
            $DescriptionList = @()
            ($_.description) -split (" ") | ForEach-Object{
                $DescriptionList += $_ -replace ("\n","")
            }
       
       
            $DescriptionString = $DescriptionList -join " "
           
            foreach($tag in $TagTable.Keys){
                if($DescriptionString -match $TagTable.$tag.pattern){
                    $DiscussionTable.Add($tag,$Matches[2])
                }
            }
        }
        return $DiscussionTable
    }

    [psobject]CheckListTemplate(){
        $Templates = @{
            Comments = @{
                T01 = (Get-Content -path "./Templates/Comments_T01.md")
            }
        }
        return $Templates
    }

    [psobject]CreateCheckList([string]$CheckList_title,[xml]$xml_rawdata){
        $CheckList_guid     = (New-Guid).Guid
        $Stig_guid          = (New-Guid).Guid
        # the checklist template contains our data
        $CheckListTemplate = @{
            cklb_version        = [int](($xml_rawdata.xml).Substring(9,1))
            title               = $CheckList_title              # we can create this
            id                  = $CheckList_guid
            stigs               = @()
            active              = $false                        # test checklist set to false, but need to define somehwhere
            mode                = 2                             # check list has this as 2, but need to define somehwere
            has_path            = $true                         # checklist has set to true, but needs to be defined somewhere
            target_data         = @{
                                    target_type     = "Computing"      # can be empty
                                    host_name       = ""      # can be empty
                                    ip_address      = ""      # can be empty
                                    mac_address     = ""      # can be empty
                                    fqdn            = ""      # can be empty
                                    comments        = ""      # we can controll what goes here after csv creation
                                    role            = "None"      # can be empty
                                    is_web_database = $false        # can be defaulted to false
                                    technology_area = ""      # can be empty
                                    web_db_site     = ""      # can be empty
                                    web_db_instance = ""      # can be empty
                                }
        }
        # there is one stig list per list
        $StigListItemTable = @{
            stig_name               = ""
            display_name            = ""
            stig_id                 = ""
            realese_info            = ""
            uuid                    = $null
            reference_identifier    = [Int64]
            size                    = [int]
            rules                   = @()
        }
       
        # there is any number of rules per stig item
        $rule_item = @{
            uuid                        = $null
            stig_uuid                   = $Stig_guid
            group_id                    = ""
            group_id_src                = ""
            rule_id                     = ""
            rule_id_src                 = ""
            weight                      = ""
            classification              = "Unknown"
            severity                    = ""
            rule_version                = ""
            group_title                 = ""
            rule_title                  = ""
            fix_text                    = ""
            false_positives             = ""
            false_negatives             = ""
            discussion                  = ""
            check_content               = ""
            documentable                = ""
            mitigations                 = ""
            potential_impacts           = ""
            third_party_tools           = ""
            mitigation_controls         = ""
            responsability              = ""
            security_overwrite_guidance = ""
            ia_controls                 = ""
            check_content_ref = @{
                href = ""
                name = ""
            }
            legacy_ids                  = @()
            ccis                        = @()
            group_tree                  = @()
            createdAt                   = ""
            UpdateAt                    = ""
            status                      = "not_reviewed"
            overrides                   = @{}
            comments                    = ""
            finding_details             = ""
        }
       
        $StigListItemTable.uuid                 = $Stig_guid
        $StigListItemTable.stig_name            = $xml_rawdata.Benchmark.title
        $StigListItemTable.display_name         = $xml_rawdata.Benchmark.group[0].rule.reference.subject
        $StigListItemTable.stig_id              = $xml_rawdata.Benchmark.id
        $StigListItemTable.realese_info         = $xml_rawdata.Benchmark.'plain-text'.'#text'[0]
        $StigListItemTable.reference_identifier = [Int64]$xml_rawdata.Benchmark.group[0].rule.reference.identifier
        $StigListItemTable.size                 = $xml_rawdata.Benchmark.Group.count
       
        # starting at the group level
        $rule_id_value = ""
        foreach($group_finding in $xml_rawdata.Benchmark.Group){
            $DiscussionTable = $this.XMLParseOut_Discussion($group_finding.rule)
            if("$($group_finding.Rule.id)" -match '(SV-.*)(_rule)'){
                $rule_id_value = $matches[1]
            }
            $group_finding.Rule.id
            $DateTimeCreated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $rule_stig_uuid = (New-Guid).Guid
            $rule_item.uuid                         = $rule_stig_uuid
            $rule_item.stig_uuid                    = $StigListItemTable.uuid
            $rule_item.group_id                     = $group_finding.id
            $rule_item.rule_id                      = $rule_id_value
            $rule_item.rule_id_src                  = $group_finding.Rule.id
            $rule_item.weight                       = $group_finding.Rule.weight
            #$rule_item.classification               = $group_finding.Rule.classification
            $rule_item.severity                     = $group_finding.Rule.severity
            $rule_item.rule_version                 = $group_finding.Rule.version
            $rule_item.rule_title                   = $group_finding.Rule.title
            $rule_item.group_title                  = $group_finding.RULE.title
            $rule_item.fix_text                     = $group_finding.Rule.fixtext.'#text'
            $rule_item.group_id_src                 = $group_finding.id
            $rule_item.false_positives              = [char]10
            $rule_item.false_negatives              = [char]10
            $rule_item.discussion                   = $DiscussionTable.VulnDiscussion
            $rule_item.check_content                = $group_finding.Rule.check.'check-content'
            $rule_item.documentable                 = if($DiscussionTable.Documentable -eq 'false'){$false}
            $rule_item.mitigations                  = $DiscussionTable.mitigations
            $rule_item.potential_impacts            = [char]10
            $rule_item.third_party_tools            = [char]10
            $rule_item.mitigation_controls          = [char]10
            $rule_item.responsability               = [char]10
            $rule_item.security_overwrite_guidance  = $DiscussionTable.SeverityOverrideGuidance
            $rule_item.ia_controls                  = [char]10
            $rule_item.check_content_ref.href       = $group_finding.Rule.check.'check-content-ref'.href
            $rule_item.check_content_ref.Name       = $group_finding.Rule.check.'check-content-ref'.name
            $rule_item.legacy_ids                   = @($group_finding.Rule.ident.'#text'[0..1])
            $rule_item.ccis                         = @($group_finding.Rule.ident.'#text'[-1])
            $rule_item.group_tree                   = @{
                                                            id = $group_finding.id
                                                            title = $group_finding.title
                                                            description = $group_finding.description
                                                        }
            $rule_item.createdAt                    = $DateTimeCreated
            $rule_item.UpdateAt                     = $DateTimeCreated
            $rule_item.overrides                    = @{}
            $rule_item.comments                     = ""
            $rule_item.finding_details              = ""
            $StigListItemTable.rules += $rule_item
        }
        $CheckListTemplate.stigs += $StigListItemTable
        return $CheckListTemplate
    }
    [psobject]GetCache(){
        $cache_file = $this.Cache.Settings.File
        $jsonObject = (Get-Content -Path $cache_file) | ConvertFrom-Json
        $hashTable = $jsonObject | ForEach-Object { $_.PSObject.Properties } | ForEach-Object {
            @{ $_.Name = $_.Value }
        }
        return $hashTable
    }
    [psobject]GetProperty([string]$PropertyName){
        $using_default  = $this.Dynamic.Settings.use_default
        $path_type      = [string]
        if($using_default){$path_type = 'default'}else{$path_type = 'custom'}

        $MyObject = switch($PropertyName){
            "host_name"{
                $this.Dynamic.Settings.host_name
            }
            "setup_complete"{
                $this.Enviornmental.Settings.SetUpComplete
            }
            "psstig_parent_path"{
                $this.Enviornmental.Settings.PSStig.Paths.$path_type.use
            }
            "stigview_parent_path"{
                $this.Enviornmental.Settings.StigViewer.Paths.$path_type.use
            }
            "use_defaults"{
                $this.Dynamic.Settings.use_defaults
            }
            "login_name"{
                $this.Dynamic.Settings.login_name
            }
            "OS"{
                $this.Dynamic.Settings.OS
            }
            '*'{
                $PropertyObject = [pscustomobject]@{
                    host_name               = $this.Dynamic.Settings.host_name
                    setup_complete          = $this.Enviornmental.Settings.SetUpComplete
                    psstig_parent_path      = $this.Enviornmental.Settings.PSStig.Paths.$path_type.use
                    stig_parent_path        = $this.Enviornmental.Settings.StigViewer.Paths.$path_type.use
                    use_default             = $this.Dynamic.Settings.use_defaults
                    login_name              = $this.Dynamic.Settings.login_name
                    OS                      = $this.Dynamic.Settings.OS
                }
                $PropertyObject
            }
            default{
                write-host "'$($PropertyName)' is not recognized" -ForegroundColor Red
            }
        }
        return $MyObject
    }

    [void]CreateCache([bool]$NewCache){
        $cache_folder           = $this.Cache.Settings.Folder
        $cache_file             = $this.Cache.Settings.File

        $create_cache_folder    = [bool]
        $create_cache_file      = [bool]

        $cache_file_created     = [bool]
        $cache_folder_created   = [bool]
        $cache_newlycreated     = [bool]

        $function_name = "CreateCache"

        # when the cache doesnt exists does it get created
        # or when you want to create a new one manually
        if(($this.Cache.Exists -eq $false) -or ($NewCache)){
            # test to see if the cache folder is there or not
            if(Test-Path -Path $cache_folder){
                $create_cache_folder = $false
            }else{
                $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "the cache folder doesn't exists, going to create it..."
                Write-Host $output_msg -ForegroundColor "yellow"
                $create_cache_folder = $true          
            }

            # create cache folder
            if($create_cache_folder){
                New-Item -path $cache_folder -ItemType "Directory"
                $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "cache folder created, good to go there..."
                Write-Host $output_msg -ForegroundColor "cyan"
                $cache_folder_created = $true
            }else{
                $cache_folder_created = $false
            }

            # test to see if the cache file is there or not
            if($cache_folder_created){
                if(Test-Path -Path $cache_file){
                    $create_cache_file = $false
                }else{
                    $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the cache file doesn't exists, going to create it..."
                    Write-Host $output_msg -ForegroundColor "yellow"
                }
            }else{
                $create_cache_file = $false
            }

            if($create_cache_file){
                New-Item -Path $cache_file -ItemType "File"
                $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "cache file created, good to go there..."
                Write-Host $output_msg -ForegroundColor "cyan"
                $cache_file_created = $true
            }else{
                $cache_file_created = $false
            }
           
            if($cache_file_created){
                $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "the cache file has been just created, need to be initalized still, lets do that"
                Write-Host -Object $output_msg -ForegroundColor "yellow"
                Set-Content -Path $cache_file -Value '{}'
                $cache_newlycreated = $true
            }else{
                $cache_newlycreated = $false
            }

            if($cache_newlycreated){
                $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "your cache file is ready to go..."
                Write-Host -Object $output_msg -ForegroundColor "Cyan"
            }
        }
    }
   
    [void]CacheMyProperties(){
        # you can cache all the current properties
        # allowed by cache rules only if the set up has been complete
        if($this.Enviornmental.Settings.SetUpComplete){
            $CacheRules = @{
                Enviornmental = @{
                    use_defaults            = $this.GetProperty("use_defaults")
                    setup_complete          = $this.GetProperty("setup_complete")
                    psstig_parent_path      = $this.GetProperty("psstig_parent_path")
                    stigview_parent_path    = $this.GetProperty("stigview_parent_path")
                }
                Dynamic = @{
                    login_name  = $this.GetProperty("login_name")
                    host_name   = $this.GetProperty("host_name")
                    OS          = $this.GetProperty("os")
                }
            }
            ($CacheRules) | ConvertTo-Json | Out-File -FilePath $this.Cache.Settings.File
        }else{
            $this.CreateCache("False")
        }
    }

    PSSTIG3([hashtable]$PathsConfiguration){
        $method_name = "PathsConfiguration"

        # alot depends on proper settings begin provided, so while this method
        # is overly verbose, it's best to know if there is issues right off the bat
        $paths_keys_list    = @('use_defaults','psstig_parent_path', 'stig_parent_path')
        $missing_keys       = $paths_keys_list | Where-Object { -not $PathsConfiguration.ContainsKey($_) }
   
        # exit condition will be raised if the proper parameters
        # are not provided
   
        if($missing_keys.count -gt 0){
            if($this.DevSettings.DEBUG_ON){
                $output_msg = "[{0}]:: {1}" -f $method_name, "you are missing some inputs..."
                Write-host -Object $output_msg -ForegroundColor "Red" }
            $exit_condition_raised = $true 
        }
        else{
            if($this.DevSettings.DEBUG_ON){
                $output_msg = "[{0}]:: {1}" -f $method_name, "there is no missing inputs..."
                Write-host -Object $output_msg -ForegroundColor "Cyan" }
            $exit_condition_raised = $false
        }
   
        # unless you provide all the required inputs, you wont do anything passed this point...
        # there is a whole workflow that takes place incase you need to reevaluate input
        if($exit_condition_raised -eq $false){
            $usingPath = [string]
            # in this portion we are evaluating the default preference set
            switch($PathsConfiguration.use_defaults){
                $true{
                    # if true, then by default the module with use the documents folder on your system
                    $this.Enviornmental.Settings.PSStig.paths.default.use      = [Environment]::GetFolderPath('MyDocuments')
                    $this.Enviornmental.Settings.StigViewer.paths.default.use  = [Environment]::GetFolderPath('MyDocuments')
                    $usingPath = "default"
                    $this.Dynamic.Settings.use_defaults = $true
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "you have selected to use the default path values..."
                        Write-host -Object $output_msg -ForegroundColor "Cyan" }

                    break
                }
   
                $false{
                    # if false, then the user provided values will be used,
                    # a check will be done to make sure they're not empty
                    if($PathsConfiguration.psstig_parent_path.length -eq 0){ $exit_condition_raised = $true }
                    if($PathsConfiguration.stig_parent_path.length -eq 0){ $exit_condition_raised = $true }
                    $usingPath = "custom"
                    $this.Dynamic.Settings.use_defaults = $false
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "you have selected to use the path values you supplied..."
                        Write-host -Object $output_msg -ForegroundColor "Cyan" }
   
                    # if the check passed, the params supplied are not empty string
                    # we can assign those paths to the class properties
                    if($exit_condition_raised -eq $false){
                        $this.Enviornmental.Settings.PSStig.paths.custom.use            = $PathsConfiguration.psstig_parent_path
                        $this.Enviornmental.Settings.StigViewer.paths.custom.use        = $PathsConfiguration.stig_parent_path
                    }

                    break
                }

                {$_ -eq $null}{
                    # you could still provide nothing for the parameter 'use_default'
                    # we can handle that here, in the default case section
                    $exit_condition_raised = $true

                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "the 'use_default' param supplied was null..."
                        Write-host -Object $output_msg -ForegroundColor "Red" }

                    break
                }

                {$_ -match '\s+'}{
                    # you could provde ' ' one or  more times
                    # this will handle that case
                    $exit_condition_raised = $true

                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "the 'use_default' param supplied can't just be blank..."
                        Write-host -Object $output_msg -ForegroundColor "Red" }

                    break
                }

                {$_.length -eq 0}{
                    $exit_condition_raised = $true

                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "the 'use_default' param supplied can't be `"`"..."
                        Write-host -Object $output_msg -ForegroundColor "Red" }
                   
                    break
                }

                {($_).GetType() -ne [bool]}{
                    # it's possible the 'use_default' can be set so something that is not a
                    # bool datatype, this will handle that case
                    $exit_condition_raised = $true

                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f $method_name, "the 'use_default' param supplied is not `$true OR `$false..."
                        Write-host -Object $output_msg -ForegroundColor "Red" }
                   
                    break
                }

                default{
                    # it's possible the user supplied us with something we didn't
                    # account for when we called this project good.
                    # this will handle those cases
                    $exit_condition_raised = $true

                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}`n{2}" -f
                        $method_name,
                        "the 'use_default' value supplied '$($PathsConfiguration.use_default)' is not allowed",
                        "supplie '`$true' or '`$false' only..."
                        Write-host -Object $output_msg -ForegroundColor "Red" }
                   
                    break
                }
            } # [end_switch]
   
            # up to this point, if there was no exit conditions raised
            # the next step is to test the values the user provided for the
            # paths required
            if($exit_condition_raised -eq $false){
                # depending on if custom or default paths are used
                # the related check will be done

                switch($usingPath){
                    "custom"{
                        if($this.DevSettings.DEBUG_ON){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "you have opted to use custom settings"
                            Write-host -Object $output_msg -ForegroundColor "Cyan" 
                        }

                        # there is two paths to test, this is the case for both custom and default
                        #  1- psstig_value check
                        if( test-path -path ($this.Enviornmental.Settings.PSStig.paths.custom.use)) {
                            $this.Enviornmental.Settings.PSStig.paths.custom.is_valid = $true

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "psstig path value '$($this.Enviornmental.Settings.PSStig.paths.custom.use)' is reachable"
                                Write-host -Object $output_msg -ForegroundColor "Cyan" 
                            }
                        }
                        else{ 
                            $exit_condition_raised = $true
                            $this.Enviornmental.Settings.PSStig.paths.custom.is_valid = $false

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "psstig path value '$($this.Enviornmental.Settings.PSStig.paths.custom.use)' is not reachable"
                                Write-host -Object $output_msg -ForegroundColor "Red" 
                            }
                       
                        }

                        # 2- stig_viewer check
                        if( test-path -path ($this.Enviornmental.Settings.StigViewer.paths.custom.use) ) {

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "stig path value '$($this.Enviornmental.Settings.StigViewer.paths.custom.use)' is reachable"
                                Write-host -Object $output_msg -ForegroundColor "Cyan" 
                            }
                            $this.Enviornmental.Settings.StigViewer.paths.custom.is_valid = $true }
                        else{
                            $exit_condition_raised = $true
                            $this.Enviornmental.Settings.StigViewer.paths.custom.is_valid = $false
                       
                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "stig path value '$($this.Enviornmental.Settings.StigViewer.paths.custom.use)' is not reachable"
                                Write-host -Object $output_msg -ForegroundColor "Red" 
                            }
                        }
                       
                        break
                    }
                    "default"{

                        if($this.DevSettings.DEBUG_ON){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "you have opted to use default settings"
                            Write-host -Object $output_msg -ForegroundColor "Cyan" 
                        }

                        # there is two paths to test, this is the case for both custom and default
                        #  1- psstig_value check
                        if( test-path -path ($this.Enviornmental.Settings.PSStig.paths.default.use)) {

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "psstig path value '$($this.Enviornmental.Settings.PSStig.paths.default.use)' is reachable"
                                Write-host -Object $output_msg -ForegroundColor "Cyan" 
                            }

                            $this.Enviornmental.Settings.PSStig.paths.custom.is_valid = $true }
                        else{

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "psstig path value '$($this.Enviornmental.Settings.PSStig.paths.default.use)' is not reachable"
                                Write-host -Object $output_msg -ForegroundColor "Red" 
                            }

                            $exit_condition_raised = $true
                            $this.Enviornmental.Settings.PSStig.paths.custom.is_valid = $false }

                        # 2- stig_viewer check
                        if( test-path -path ($this.Enviornmental.Settings.StigViewer.paths.default.use) ) {

                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "stig path value '$($this.Enviornmental.Settings.StigViewer.paths.default.use)' is reachable"
                                Write-host -Object $output_msg -ForegroundColor "Cyan" 
                            }
                            $this.Enviornmental.Settings.StigViewer.paths.default.is_valid = $true }
                        else{
                            $exit_condition_raised = $true
                            $this.Enviornmental.Settings.StigViewer.paths.default.is_valid = $false
                       
                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                $method_name,
                                "stig path value '$($this.Enviornmental.Settings.StigViewer.paths.default.use)' is not reachable"
                                Write-host -Object $output_msg -ForegroundColor "Red" 
                            }
                        }
                    }
                } #[end_switch]
            }

            # it would be fair to assume that, if you went to the trouble of making a module
            # and the user went through the trouble of downloading it, that there should be
            # an option for the user to have a chance to provide paths that work in the event
            # that the paths didnt work on the first go
            if($exit_condition_raised -eq $true){
                $GIVEUP     = $false
                $reprompted = $false
                $input_value = [string]
                $alreadyPrompted_heading = 0
                do{
                    # assuming both paths are wrong, the message should explictly make mention of that
                    if(((($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid) -eq $false) -and (($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid) -eq $false))){
                        # only one parameter was invalid, so we
                        # use this var to do the evaluation
                        $pathWrong          = [string]
                        $test_input_value   = [bool]

                        # this var sets to true to avoid going over the logic
                        # that would otherwise run when only one path is unreachable
                        $reprompted = $true

                        $pathWrong = "StigViewer"
                        if($alreadyPrompted_heading -eq 0){
                            $input_msg = "{0}`n{1}" -f
                                "Looks like both of the paths you provide are not reachable, if you would like to provide alternate paths",
                                "you can do so by typing them now or type 'end' to quite all together..."
                            Write-Host -Object $input_msg -ForegroundColor 'yellow'
                        }

                        $input_msg = "{0}" -f
                            "'stig_viewer fullpath' or 'end'"
                        Write-Host -Object $input_msg -ForegroundColor 'yellow'

                        $input_value = Read-Host -Prompt "provide your input, and press any key to continue"
                        if($input_value -ne "end"){
                            $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use = $input_value
                            $test_input_value = $true
                        }

                        # once the user has provided the path again, test the path provided, and revaluate
                        if($test_input_value){
                            if($this.DevSettings.DEBUG_ON){
                                $output_msg = "[{0}]:: {1}" -f
                                    $method_name,
                                    "testing path $($this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use)"
                                Write-Host -Object $output_msg -ForegroundColor Yellow
                            }
                            if(Test-Path -Path $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use){
                                $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $true
                            }else{
                                $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $false
                            }
                        }

                        if($input_value -eq "end"){
                            $GIVEUP = $true
                        }

                        if($GIVEUP -eq $false){
                            $pathWrong = "PSStig"
                            $input_msg = "{0}" -f
                                "'psstig fullpath' or 'end', press any key to continue"
                            Write-Host -Message $input_msg -ForegroundColor 'yellow'
                            $input_value = Read-Host -Prompt "provide your input, and press any key to continue"

                            if($input_value -ne "end"){
                                $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use = $input_value
                                $test_input_value = $true
                            }
   
                            # once the user has provided the path again, test the path provided, and revaluate
                            if($test_input_value){
                                if($this.DevSettings.DEBUG_ON){
                                    $output_msg = "[{0}]:: {1}" -f
                                        $method_name,
                                        "testing path $($this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use)"
                                    Write-Host -Object $output_msg -ForegroundColor Yellow
                                }
                                if(Test-Path -Path $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use){
                                    $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $true
                                }else{
                                    $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $false
                                }
                            }
                        }

                        if($input_value -eq "end"){
                            $GIVEUP -eq $true
                        }
                        $test_input_value = $false          
                    }
   
                    # dont prompt again if the first condition to prompt was met
                    if($reprompted -eq $false){
                        if($alreadyPrompted_heading -eq 0){
                            $input_msg = "{0} {1}" -f
                                "Looks like one of the paths you provide is not reachable, if you would like to provide alternate path",
                                "you can do so by typing it now or type 'end' to quite all together..."
                            Write-Host -Object $input_msg -ForegroundColor 'yellow'
                        }

   
                        # in the event that only one of the two was incorrect,
                        if(($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid) -or ($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid)){
                            # only one parameter was invalid, so we
                            # use this var to do the evaluation
                            $pathWrong          = [string]
                            $test_input_value   = [bool]

                            if($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid -eq $false){
                                $pathWrong = "PSStig"
                                $input_msg = "{0}" -f "`n'psstig fullpath' or 'end'"
                                Write-Host -Message $input_msg -ForegroundColor 'yellow'
                                $input_value = Read-Host -Prompt "provide your input, and press any key to continue"
   
                                if($input_value -ne "end"){
                                    $this.Enviornmental.Settings.PSStig.paths.$usingPath.use = $input_value
                                    $test_input_value = $true
                                }
                            }

                            if($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid -eq $false){
                                $pathWrong = "StigViewer"
                                $input_msg = "{0}" -f "`n'stig_viewer fullpath' or 'end'"
                                Write-Host -Message $input_msg -ForegroundColor 'yellow'
                                $input_value = Read-Host -Prompt "provide your input, and press any key to continue"
   
                                if($input_value -ne "end"){
                                    $this.Enviornmental.Settings.StigViewer.paths.$usingPath.use  = $input_value
                                    $test_input_value = $true
                                }
                            }

                            # once the user has provided the path again, test the path provided, and revaluate
                            if($test_input_value){
                                if($this.DevSettings.DEBUG_ON){
                                    $output_msg = "[{0}]:: {1}" -f
                                        $method_name,
                                        "testing path $($this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use)"
                                    Write-Host -Object $output_msg -ForegroundColor Yellow
                                }
                                if(Test-Path -Path $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.use){
                                    $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $true
                                }else{
                                    $this.Enviornmental.Settings.$pathWrong.paths.$usingPath.is_valid = $false
                                }
                            }

                            if($input_value -eq "end"){
                                $GIVEUP = $true
                            }
                        }
                        $reprompted = $false
                    }

                    $alreadyPrompted_heading = 1
                }until(
                    ($GIVEUP -eq $true) -or (
                        (
                            (($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid)        -eq $true) -and
                            (($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid)    -eq $true)
                        )
                    )
                )
               
                # if you gave up on the initial set up, any of the paths are not valid, the setup is not complete
                if($GIVEUP -eq $true){
                    $this.Enviornmental.Settings.SetUpComplete = $false
                }
                if($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid -eq $false){
                    $this.Enviornmental.Settings.SetUpComplete = $false
                }
                if($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid -eq $false){
                    $this.Enviornmental.Settings.SetUpComplete = $false
                }

                if( ((($this.Enviornmental.Settings.PSStig.paths.$usingPath.is_valid)        -eq $true) -and
                    (($this.Enviornmental.Settings.StigViewer.paths.$usingPath.is_valid)    -eq $true)) -and
                    ($GIVEUP -eq $false)){
                        $this.Enviornmental.Settings.SetUpComplete =$true
                }
            }
            else{
                $this.Enviornmental.Settings.SetUpComplete = $true
            }

            # set up will always cache properties
            if($this.Enviornmental.Settings.SetUpComplete -eq $true){
                $this.CacheMyProperties()
            }
        }
    }
    # *--*--*--*--*--*--*--*--*--*--*--* [Initialize] *--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*-- #
   
    [psobject]GetRawSTIGXMLData([string]$stig_xml_file){
        $function_name = "GetRawSTIGXMLData"
        $my_stig_files = $null
        [xml]$my_stig_rawdata = $null
        $cache_exists = [bool]
        # if you have a cache, you dont need to run set up again
        if(test-path -path $this.Cache.settings.File){
            $cache_exists = $true
        }else{
            $cache_exists =$false
        }
        if($cache_exists){
            $my_stig_files = (Get-ChildItem -path ($this.GetCache().Enviornmental.stigview_parent_path) -Recurse)
            foreach($itemreturned in $my_stig_files){
                if($itemreturned.Name -match $stig_xml_file){
                    [xml]$my_stig_rawdata = Get-Content -path $itemreturned.FullName
                }
            }

        }else{
            if($this.DevSettings.DEBUG_ON){
                $output_msg = "[{0}]:: {1}" -f 
                $function_name,
                "i can't seem to tell if you ran the initial setup before, please run it again and then run this function again"
                Write-Host $output_msg -ForegroundColor Yellow
            }
        }
        return $my_stig_rawdata
    }
    # *--*--*--*--*--*--*--*--*--*--*--* [XML READ] *--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*--*-- #
}

# extrat path C:\Users\abraham.hernandez\Documents\Software\STIGViewer_64_3-2-0

# the user will always need to run set up first
# unless they already did so before
Set-Location -path "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library"

$PSSTIG3 = [PSSTIG3]::new(
    @{
        use_defaults = $false
        psstig_parent_path = "./test_path"
        stig_parent_path   = "./test_path"
    }
)


$xml_rawdata = $PSSTIG3.GetRawSTIGXMLData('backup.xml')


$PSSTIG3.XMLParseOut_Discussion($xml_rawdata.Benchmark.group.rule.Description[0])
$checklist = $PSSTIG3.CreateCheckList('test_checklist',$PSSTIG3.GetRawSTIGXMLData('backup.xml'))
$checklist | ConvertTo-Json -Depth 5| Out-File ./test_checklistfrompsstig.json

# after setting up where your psdata will be save an where the stig data is
# you can now read in the xml data from a stig


$PSSTIG3.GetProperty('*')
$PSSTIG3.CacheMyProperties()
$PSSTIG3.CreateCache("false")
$PSSTIG3.Cache.Settings


Get-ChildItem -path ($PSSTIG3.GetCache().Enviornmental.stigview_parent_path) -Recurse
Get-ChildItem -path ($this.GetCache().Enviornmental.stigview_parent_path) -Recurse




$sys_gen = Get-Content -path './New Checklist.json' | ConvertFrom-Json
$SEFL_gen = Get-Content -path './test_checklistfrompsstig.json' | ConvertFrom-Json

$sys_gen.target_data
$SEFL_gen.target_data

$sys_gen
$SEFL_gen

$sys_gen.stigs.reference_identifier.GetType()
$SEFL_gen.stigs.reference_identifier.GetType()

$sys_gen.stigs.rules[0].Documentable
$SEFL_gen.stigs.rules[0].documentable
$PSSTIG3.XMLParseOut_Discussion($xml_rawdata.Benchmark.group.rule[0])

$xml_rawdata.Benchmark.group.rule.id
