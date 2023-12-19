Class PSSTIG{
    # this section defines the class properties
    $DevSettings = @{
        #TODO:: this will need to be reworked to be scoped to a more appropriate name
        # this option has evoled to the point that it's not just for development usage
        # it's used mainly for user feedback.
        DEBUG_ON = $true
    }
   
    $Dynamic = @{
        # settings in this category pretain to internal paths and values
        # defined by the module at runtime
        Settings = @{
            use_defaults    = [bool]
            OS              = [System.Environment]::OSVersion.Platform
            host_name        = [System.Net.Dns]::GetHostName()
            login_name      = Invoke-Command -ScriptBlock{
                $username = whoami
                $username
            }

            # testing was done on unix and windows systems
            # at least in the context of the module itself, it needs to know
            # how paths will work given the OS its being used on
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

    $stowed_credentials = @()
    # store paths to resources used by the module
    $paths_table = @{
        host_list = @{
            path    = "$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)Sources$($this.Dynamic.Settings.Separator)host_list.csv"
            type    = 'csv'
            table   = @{
                # 'column_list' defines all the columns in the table, 'is_null' defined weather it can be null or not
                # 'data_type' is the defined datatype that entry can be, and 'use_default' defines if there is some defualt that entry will have
                column_list = @(
                    @{id =                      @{is_null = $true;      data_type = [int];      use_default = $true}},
                    @{datetime_created =        @{is_null = $true;      data_type = [string];   use_default = $true}},
                    @{added_by =                @{is_null = $true;      data_type = [string];   use_default = $true}},
                    @{checklist_name =          @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{from_source =             @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{from_collection =         @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{access_name =             @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{is_sql_server =           @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{using_sql_login =         @{is_null = $true;      data_type = [int];      use_default = $false}}
                    @{sql_instance_name =       @{is_null = $true;      data_type = [string];   use_default = $false}},
                    @{enclave =                 @{is_null = $true;      data_type = [string];   use_default = $false}},
                    @{domain =                  @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{need_creds =              @{is_null = $false;     data_type = [int];      use_default = $false}},
                    @{cred_type_to_use =        @{is_null = $true;      data_type = [string];   use_default = $false}},
                    @{host_type =               @{is_null = $false;     data_type = [string];   use_default = $false}},
                    @{use_general_properties =  @{is_null = $false;     data_type = [int];      use_default = $false}},
                    @{where =                   @{is_null = $true;      data_type = [string];   use_default = $false}},
                    @{operator =                @{is_null = $true;      data_type = [string];   use_default = $false}},
                    @{is_this =                 @{is_null = $true;      data_type = [string];   use_default = $false}}
                )
                # is use_identity is true, identiy_properties needs to be defined
                use_identity        = $true
                identity_properties = @{
                    is_set          = $true
                    is              = 'id'
                    with_seed       = 0
                    and_increment   = 1
                }

                # if all_columns_required is false, you need to define if there are some exclusion
                # all_columns_required is a switch. not every update needs all the columns to be required
                # not all columns are required when you expect to have some default values set for the ones not included
                all_columns_required    = $false
                # if with_some_exclusions is true, the exclusion list needs to be defined
                with_some_exclusions    = $true
                exclusion_list          = @('id','datetime_created','added_by')

                # each thing in your exlusion_list needs to be linked to something that will define it's default property
                use_default_for_exclusion_list_items = @{
                    id                  = [int]
                    datetime_created    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                    added_by            = [Environment]::UserName
                }
               
                # any entry that can be null where the  is_null value is set to true  needs to be defined
                null_exception_list = @(
                    # any column in this hashtable needs to be a column
                    @{use_sql_login = @{
                        under_some_condition    = $false
                        input_dependant         = $false
                    }}
                    @{cred_type_to_use = @{
                        under_some_condition    = $true
                        input_dependant         = $true
                    }}
                    @{enclave = @{
                        under_some_condition    = $false
                        input_dependant         = $false
                    }}
                    @{domain = @{
                        under_some_condition    = $false
                        input_dependant         = $false
                    }}
                    @{checklist_name = @{
                        # any key with under_some_condition set to false can always be null
                        under_some_condition    = $false
                        input_dependant         = $false
                    }}
                    @{where = @{
                        # any key with under_some_condition set to true, can be null under their constraint
                        under_some_condition    = $true;
                        input_dependant         = $true
                    }}
                    @{operator = @{
                        under_some_condition    = $true
                        input_dependant         = $true
                    }}
                    @{is_this = @{
                        under_some_condition    = $true
                        input_dependant         = $true
                    }}
                    @{sql_instance_name = @{
                        under_some_condition    = $true
                        input_dependant         = $true
                    }}
                )

                # input_dependant_table is only applicable to keys in the null_exception_list where input_dependant is true
                input_dependant_table = @{
                    cred_type_to_use    = @{need_creds              = 0}
                    where               = @{use_general_properties  = 1}
                    operator            = @{use_general_properties  = 1}
                    is_this             = @{use_general_properties  = 1}
                    sql_instance_name   = @{is_sql_server           = 0}
                }
            }
        }
        finding_rule = @{
            path = "$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)Sources$($this.Dynamic.Settings.Separator)finding_rule.json"
        }
    }
    $Enviornmental = @{
        # settings in this category relate to paths and settings as defined
        # by the user at runtime
        Settings = @{
            Stig_Viewer_path    = [string]
            Report_path         = "$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)Reports"
            SetUpComplete       = $false
            DEBUG_ON            = [bool]
            PSStig              = @{
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
        # settings under this section pertain to how the cache works
        #TODO:: while things work, it still needs to be fleshed out more in order to call this a functional
        #       read/write through cache
        Settings = @{
            Exists  = $false
            Folder  = "$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)Cache$($this.Dynamic.Settings.Separator)"
            File    = "$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)Cache$($this.Dynamic.Settings.Separator)PSItemCache.json"
        }
    }
    $ReportsLists = @(
        "Findings"
    )
    [void]stashCred([hashtable]$fromSender){
        # declare vars
        $show_message_params = @{
            method_name  = "stashCreds"
            message      = ""
            message_type = ""
        }

        if($fromSender.from_PIV -eq $false){
            $securePassword = ConvertTo-SecureString -String $fromSender.pw -AsPlainText -Force
            $credentials    = New-Object -TypeName PSCredential -ArgumentList $fromSender.user_name, $securePassword
        }else{
            #TODO:: need to add the ability to prompt when using PIV
            $securePassword = ConvertTo-SecureString -String $fromSender.pw -AsPlainText -Force
            $credentials    = New-Object -TypeName PSCredential -ArgumentList $fromSender.user_name, $securePassword
        }
        
        $this.stowed_credentials += New-Object PSObject -Property @{
            cred_name       = $fromSender.cred_name
            cred_is         = $fromSender.cred_is
            for_domain      = $fromSender.for_domain
            for_this_host   = $fromSender.for_this_host
            user_name       = $credentials.UserName
            pw              = $credentials.Password
        }

        $show_message_params.message_type   = "success"
        $show_message_params.message        = "credential stowed successfully"
        Show-Message @show_message_params
    }
    [void]RunAudit([hashtable]$fromSender){
        # declare vars
        $show_message_params = @{
            method_name  = "RunAudit"
            message      = ""
            message_type = ""
        }
        $my_hosts           = $this.getDataFrom('host_list')
        $my_sessions_table  = @{}
        $total_seesion      = $my_hosts.count
        $session_counter    = 1
        $my_computer_name   = & hostname

        
        foreach($my_host in $my_hosts){
            # the session name is defined by the access_name 
            $session_name = "{0}" -f "$($my_host.access_name)"
            
            if($my_host.using_sql_login -eq 0){
                $cred_is = 'WindowsAuth'
            }else{
                $cred_is = 'SQLLogin'
            }
        
            # credentials are searched for for the credential
            $my_creds = $this.getStashedCred(@{
                cred_name       = $my_host.cred_type_to_use
                cred_is         = $cred_is
                for_domain      = $my_host.domain
                for_this_host   = $my_host.access_name
            })
            
            # the credentials are used to create the session for the host
            $for_session = New-Object -TypeName PSCredential -ArgumentList  $my_creds.user_name,$my_creds.pw
            $session_created = [bool]
            try{
                $session_created    = $true
                $my_session         = (New-PSSession -Name $session_name -ComputerName "$($my_host.access_name)" -Credential $for_session  -ErrorAction SilentlyContinue)
            }catch{
                $session_created    = $false
                $my_session         = $null
            }
            
            if($session_created){
                $show_message_params.message_type = 'success'
                $session_counter = $session_counter + 1
                $show_message_params.message = "[session ($session_counter of $total_seesion)] ---- [$my_computer_name] ---- [to] ---- [$($my_host.access_name)]--[status:( o )]-->"
            }else{
                $show_message_params.message_type = 'failed'
                $session_counter = $session_counter -1
                $show_message_params.message = "[session ($session_counter of $total_seesion)] ---- [$my_computer_name] ---- [to] ---- [$($my_host.access_name)]--[status:( x )]-->"
            }
            #display feedback
            Show-Message @show_message_params

            if($session_created){
                # the session it self if used to define the session properties to then add then to host itself
                $my_sessions_table.Add($my_session.name,@{})
                $my_sessions_table.($my_session.name) = @{
                    the_session = $my_session
                    state       = $my_session.State
                    id          = $my_session.id
                    my_host     = $my_host
                }
            }
            
        }
        $show_message_params.message_type = 'info'
        $show_message_params.message = "Type 'Y' to continue with the audit, or 'N' to terminate this action"
        Show-Message @show_message_params
        $user_wants_to_continue = read-host 

        $sessions_closed = [bool]
        if($user_wants_to_continue -eq 'N'){
            $sessions_closed = $true
            # on mac 'Get-Session' is not defined
            Get-Session -name * | Remove-PSSession | Out-Null
        }

        if($user_wants_to_continue -eq 'Y'){
            $sessions_closed = $false
        }

        if($sessions_closed){
            $show_message_params.message_type = 'Info'
            $show_message_params.message = "total sessions closed: ($session_counter)"
        }else{
            $show_message_params.message_type = 'Info'
            $show_message_params.message = "total sessions open: ($session_counter)" 
        }
        # dislay feedback
        Show-Message @show_message_params

        if($sessions_closed){
            return
        }

        # script library gets defined
        $scripts_list = $this.GetScriptProperties()
        $my_seach_conditions = @{
            where       = 'status'
            operator    = 'eq'
            is_this     = 'not_reviewed'
        }
        foreach($session in $my_sessions_table){
            # each host object defines what  kind of properties to use
            # if the object value is '1' then it will use the defined GeneralUpdateProperties defined by you
            # it might be better to think of general update properties as a categorical search filter, there can be many, but this one is do an audit
            if($my_sessions_table.$session.my_host.use_general_properties -eq 1){
                $my_sessions_table.$session.my_host.where      = $my_seach_conditions.where
                $my_sessions_table.$session.my_host.operator   = $my_seach_conditions.operator
                $my_sessions_table.$session.my_host.is_this    = $my_seach_conditions.is_this
            }

            # data is the returned from the select list where the search criteria is met
            $my_data =  $this.SelectFromCheckThisList(@{
                ForHostName         = $my_sessions_table.$session.my_host.checklist_name                                                         
                FromThisSource      = $my_sessions_table.$session.my_host.from_source                                                                 
                FromThisCollection  = $my_sessions_table.$session.my_host.from_collection                                                                         
                Where               = $my_sessions_table.$session.my_host.where                                                                                 
                Operator            = $my_sessions_table.$session.my_host.operator                                                                                      
                isThis              = $my_sessions_table.$session.my_host.is_this                                                                           
            })            
            # the data is then added to the sessions table
            $my_sessions_table.$session.Add('checklist_data',$my_data)

            # all the scripts are then added to each session?
            # would be better to add them only once
            $my_sessions_table.$session.Add('script_table',@{})
            foreach($script in $scripts_list.keys){
                $my_sessions_table.$session.script_table.Add($script,$scripts_list.$script)
            }
        }

        # $my_data =  $PSSTIG.SelectFromCheckThisList(@{
        #     ForHostName         = $my_host.checklist_name                                                         
        #     FromThisSource      = $my_host.from_source                                                                 
        #     FromThisCollection  = $my_host.from_collection                                                                         
        #     Where               = 'status'                                                                                
        #     Operator            = 'eq'                                                                                     
        #     isThis              = 'not_reviewed'                                                                        
        # }) 
        # a counter for each session is seeded
        $total_jobs_needed = [int]
        foreach($session in $my_sessions_table.keys){
            # a counter for each session is seeded
            $total_jobs_needed = 0

            # the seassion then looks in its checklists, for the finding id 
            foreach($finding in $my_data){
            #foreach($finding in $my_sessions_table.$session.checklist_data){
                if($finding.group_id -match '(V-)(.*)'){
                    $finding_id = $Matches[2]
                }else{
                    $finding_id = $Null
                }
                
                # since at this point the checklist has been filtered, we need to see what kind of script will be needed to do the work
                # this is done by using the finding id and the script id wich will be the same
                #foreach($script in $my_sessions_table.$session.script_table.keys){
                foreach($script in $scripts_list.keys){
                    #$script_finding_id  =  $my_sessions_table.$session.script_table.$script.finding_id
                    $script_finding_id  =  $scripts_list.$script.finding_id
                    if($script_finding_id -match $finding_id){
                        # $script_path = $my_sessions_table.$session.script_table.$script.script_path
                        $script_path = $scripts_list.$script.script_path

                        # matching the criteria means a script will be ran, that will happen in it's own job
                        # the counter will track how many jobs
                        $total_jobs_needed = $total_jobs_needed + 1
                    }
                }
            }
        }

        # each session will kick off their jobs in batches
        foreach($session in $my_sessions_table.keys){
            # each session will define how many jobs to run and how many batches to run
            # let the sender set the batch limit
            # for not just test with a batchsize of 10
            $batchSize = 10
            $total_jobs_needed = 100
            #for ($i = 1; $i -le $total_jobs_needed; $i += $fromSender.Batchsize){
            for ($i = 1; $i -le $total_jobs_needed; $i += $batchSize){
                $batchStart = $i
                $batchEnd = [math]::Min($i + $batchSize - 1, $total_jobs_needed)
                write-host   "starting batch at: $batchStart" -ForegroundColor cyan
                write-host   "batch ends at: $batchEnd" -ForegroundColor cyan

                $my_jobs = $batchStart..$batchEnd
                foreach($job in $my_jobs){
                    
                }
            }
        }

    }

    [psobject]getStashedCred([hashtable]$fromSender){
        # declare vars
        $show_message_params = @{
            method_name  = "stashCreds"
            message      = ""
            message_type = ""
        }

        $my_cred =  $this.stowed_credentials | Select-Object -Property * |
        Where-Object {$_.for_domain -match "$($fromSender.for_domain)" -and ($_.for_this_host -match "$($fromSender.for_this_host)") -and ($_.cred_name -eq "$($fromSender.cred_name)") -and ($_.cred_is -eq "$($fromSender.cred_is)")}

        $no_cred_found = [bool]
        if($null -eq $my_cred){
            $no_cred_found = $true
        }else{
            $no_cred_found = $false
        }

        if($no_cred_found){
            $show_message_params.message_type = 'failed'
            $show_message_params.message = "no credential was found that for domain'$($fromSender.for_domain)' with host name '$($fromSender.for_this_host)'"
        }else{
            $show_message_params.message_type = 'success'
            $show_message_params.message = "credential found...'"       
        }
        # display feedback
        Show-Message @show_message_params
        return $my_cred
    }
    [PSObject]GetScriptProperties(){
        # declare vars
        $show_message_params = @{
            method_name  = "GetScriptProperties"
            message      = ""
            message_type = ""
        }
        $script_library_object  = $null
        $script_library_exists  = [bool]
        $separator              = $this.Dynamic.Settings.Separator
       
        # script library is set within the the module itself
        $path_to_script_library = "$(Get-ScriptPath)$($separator)ScriptLibrary"
       
        try{
            $script_library_exists = $true
            $script_library_object = Get-ChildItem -Path $path_to_script_library -ErrorAction Stop

            $show_message_params.message_type   = "success"
            $show_message_params.message        = "the path to the script library '$path_to_script_library' is reachable"
        }catch{
            $script_library_exists = $false
            $show_message_params.message_type   = "failed"
            $show_message_params.message        = "the path to the script library '$path_to_script_library' is not reachable or does not exist"
        }
        # display some feedback
        Show-Message @show_message_params
        if(-not($script_library_exists)){
            return $false
        }
       
        $scripts_list = @()
        $show_message_params.message_type   = "info"
        $show_message_params.message        = "gathering some script file properties..."
        $script_library_object | ForEach-Object{
            $scripts_list +=  $_ | Select-Object -Property ('FullName','BaseName','extension')
        }
        # display some feedback
        Show-Message @show_message_params

        $show_message_params.message_type   = "info"
        $show_message_params.message        = "defining script file properties..."
        Show-Message @show_message_params

        # each script file name from the script_library gets parsed out using regular expression
        $script_category_table = @{}
        foreach($script in $scripts_list){

            # we are looking at only ps1 scripts currently
            if($script.Extension -eq '.ps1'){

                # from the script file name, we want identify three parts, the findingid, the script type it is
                # and the script name
                $script_name_is_valid = $false
                if(($script.BaseName) -match '([0-9]+)_(CHECK|REMEDIATE)_(.*)' ){
                    $script_id              = $matches[1]
                    $script_type            = $matches[2]
                    $script_simple_name     = $matches[3]
                    $script_name_is_valid   = $true

                    $show_message_params.message_type   = "success"
                    $show_message_params.message        = "script file '$($script.BaseName)' is in the correct format"
                }else{
                    $script_id              = $null
                    $script_type            = $null
                    $script_simple_name     = $null
                    $script_name_is_valid   = $true

                    $show_message_params.message_type   = "success"
                    $show_message_params.message        = "part the naming of your script '$($script.BaseName)' file is incorrect"
                }
                # display some feedback
                Show-Message @show_message_params

                # if the script file is correctly named then we can get the content of the file itself
                $script_string = ""
                $script_content_read = [bool]
                if($script_name_is_valid){
                    try{
                        $script_content_read = $true
                        $script_string  = Get-Content $script.FullName
                        $show_message_params.message_type   = "info"
                        $show_message_params.message        = "the script file content for script '$($script.BaseName)' was read in..."

                    }catch{
                        $script_content_read = $false
                        $show_message_params.message_type   = "failed"
                        $show_message_params.message        = "the script file content for script '$($script.BaseName)' was read not read in..."
                    }
                    # display some feedback
                    Show-Message @show_message_params
                    if(-not($script_content_read)){
                        return $false
                    }
                }else{
                    return $false
                }

                # scripts in the script library have two commented lines at the top
                # that is the convention of scripts included in this module
                # here we use regular expression to define properties
                if($script_content_read){
                    $script_level       = $null
                    $script_description = $null

                    # here we look at the first line and figure out what level the script is for
                    # level can be either 'host', 'instance', or 'database' level
                    $script_level_defined = [bool]
                    if($script_string[0] -match '(.*) : (.*)'){
                        $script_level_defined = $true
                        $script_level = $matches[2]
                       
                        $show_message_params.message_type   = "info"
                        $show_message_params.message        = "script level definition is in the proper format..."

                    }else{
                        $script_level_defined = $false
                        $show_message_params.message_type   = "failed"
                        $show_message_params.message        = "unable to define script level for script '$($script.BaseName)'"
                    }
                    # display feedback
                    Show-Message @show_message_params

                    $script_desc_defined = [bool]
                    if($script_level_defined){

                        # here we look for the description on line two of the script content
                        if($script_string[1] -match '(.*) : (.*)'){
                            $script_desc_defined = $true
                            $script_description = $matches[2]

                            $show_message_params.message_type   = "info"
                            $show_message_params.message        = "script description definition is in the proper format..."
                        }else{
                            $script_desc_defined = $false
                            $show_message_params.message_type   = "failed"
                            $show_message_params.message        = "unable to define script description for script '$($script.BaseName)'"
                        }
                        # display feedback
                        Show-Message @show_message_params
                    }else{
                        return $false
                    }
               
                    # lastly, the keys in the hashtable are defined
                    if($script_desc_defined){
                        $script_category_table.add($script_simple_name,@{
                            finding_id          = $script_id
                            script_type         = $script_type
                            script_level        = $script_level
                            script_description  = $script_description
                            script_string       = $script_string
                            script_path         = $script.FullName
                            script_name         = $script.BaseName
                        })
                    }else{
                        return $false
                    }
                }else{
                    return $false
                }
            }else{
                $show_message_params.message_type   = "failed"
                $show_message_params.message        = "the extension for file '$($script.BaseName)' is not '$($script.extension)'"
                # display feedback
                Show-Message @show_message_params
            }
        } # end foreach

        # provide some aggregate information from this method
        $show_message_params.message_type   = "feed_back"
        $show_message_params.message        = "there is a total of '$($script_category_table.count)' script(s) in your script library"
        # display feedback
        Show-Message @show_message_params

        return $script_category_table
    }
    [void]AddXMLDataToCollection([hashtable]$fromSender){
        $method_name    = "AddXMLDataToCollection"
        $output_msg     = $null
        Copy-Item -Path $fromSender.from_this_xml_data -Destination  $fromSender.collection_path

        $output_msg = $output_msg -f
        $method_name,
        "made a copy of your xml data from this location '$($fromSender.from_this_xml_data)', and saved it to this location '$($fromSender.collection_path)'"
        Write-Host $output_msg -ForegroundColor Cyan

    }
    [psobject]getDataFrom([string]$this_file){
        # declare vars
        $show_message_params = @{
            method_name  = "getDataFrom"
            message      = ""
            message_type = ""
        }

        $can_read_file  = [bool]
        $my_rawdata     = $null
        # data need to be read in from the source defined in the class parameter
        try {
            $can_read_file  = $true
            $my_rawdata     = Get-Content $this.paths_table.$this_file.path -ErrorAction Stop -Raw
            $show_message_params.message_type   = 'success'
            $show_message_params.message        = "was able to read data from resource '$($this_file)'"
        }catch{
            $can_read_file  = $false
            $show_message_params.message_type   = 'failed'
            $show_message_params.message        = "was unable able to read data from resource '$($this_file)'"
        }
        #display feedback
        Show-Message @show_message_params                
        if(-not($can_read_file)){
            return $false
        }

        $my_data            = $null
        $can_convert_data   = [bool]
        switch(($this.paths_table.$this_file).type){
            'csv'{
                try{
                    $my_data    = $my_rawdata | ConvertFrom-Csv -ErrorAction Stop
                    $can_convert_data                   = $true
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "data from source was converted..."
                }catch{
                    $can_convert_data                   = $false
                    $show_message_params.message_type   = 'failed'
                    $show_message_params.message        = "data from source was not able to be converted..."
                }
            }
            'json'{
                try{
                    $my_data    = $my_rawdata | ConvertFrom-Json -ErrorAction Stop
                    $can_convert_data                   = $true
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "data from source was converted..."
                }catch{
                    $can_convert_data                   = $false
                    $show_message_params.message_type   = 'failed'
                    $show_message_params.message        = "data from source was not able to be converted..."
                }
            }
            default{
                $show_message_params.message_type   = 'failed'
                $show_message_params.message        = "the file type for '$($this_file)' is not defined"
                # display feedback
                Show-Message @show_message_params
                return $false
            }
        }
        # display feedback
        Show-Message @show_message_params
        if(-not($can_convert_data)){
            $my_rawdata = $null
            return $false
        }

        $my_rawdata = $null
        return $my_data
    }
    [void]insertInto([hashtable]$fromSender){
        # declare vars
        $show_message_params = @{
            method_name  = "addDataTo"
            message      = ""
            message_type = ""
        }

        # data is read in by invoking the 'getDataFrom' method
        $my_data = $this.getDataFrom(($fromSender.this_file))

        # since data can be structured differently, i.e. some in csv format, some in json
        # its required to get the file's type
        $my_path_table = $this.paths_table.($fromSender.this_file)

        # define the desired order of property names
         $desiredOrder = @($my_path_table.table.column_list.keys)
        # depending on the type of the file, the updatable fields are set differently,
        # getting column headings from csv format will be different from json or xml, etc...
        
        $missing_columns            = @()
        $there_are_missing_columns  = [bool]
        

        # the switch is incharge of handling the file format the data is stored in
        # default conditions are considered to be exceptions when the file type is undefined
        # in the switch
        $is_valid_type  = [bool]
        switch($my_path_table.type){
            "csv"{
                $is_valid_type      = $true
                #-Note::    Handling Of Missing Paramters In Insert Method:
                #           Columns can be exluded from the insert statement only when that column, as defined in tables.column_list as
                #           the property use_default set to true.
                #           Any ommited column in the insert statement with a 'use_default' set to 'false' is considered to be an exception.

                # step 1.0) comparing of the users input to the defined columns in tables.column_list is done
                $missing_columns    = $my_path_table.table.column_list.keys | Where-Object { -not $fromSender.this_data.ContainsKey($_)}

                # columns are considered to have been ommited only when there is a difference defined in 'misssing_columns'
                if($missing_columns.count -ne 0){
                    $missing_columns_string    = $missing_columns -join (',')
                    $there_are_missing_columns = $true
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "update command excluded the following column names '$missing_columns_string'"
                }else{
                    $there_are_missing_columns  = $false
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "update command did did not exclude any columns"
                }
                #display feedback
                Show-Message @show_message_params

                # step 1.1) in the event that the use's input ommited some columns, those column's use_default property is evaluted
                #           the results of the evaluation will define if an exception is triggered or not
                $these_columns_cannot_be_ommited = @()
                if($there_are_missing_columns){
                    foreach($column in $my_path_table.table.column_list.keys){
                        $use_defult = $my_path_table.table.column_list.$column.use_default

                        # only the columns in the column list whos use_default property set to false can be excluded
                        if(-not($use_defult)){
                            if($missing_columns -contains $column){
                               $these_columns_cannot_be_ommited += $column
                            }
                        }
                    }
                }

                # step 1.2) the exception is defined in the event that there is anything other than 0 columns exluded with a use_default of false
                #           if columns are missing, but their use_default is true, then on exception will be considered for defining
                $raise_exception_missing_required_cols = [bool]
                if(-not($these_columns_cannot_be_ommited).count -eq 0){
                    $raise_exception_missing_required_cols  = $true
                    $show_message_params.message_type   = 'failed'
                    $show_message_params.message        = "your update request is missing some properties"
                }else{
                    $raise_exception_missing_required_cols  = $false
                    $show_message_params.message_type   = 'success'
                    $show_message_params.message        = "update request included all required parameters"
                }
                # display feedback
                Show-Message @show_message_params

                # step 1.3) the method will terminate depending on the results of the workflow up to this point
                if($raise_exception_missing_required_cols){
                    return
                }

                # step 1.4) columns that are ommited from the insert statement, but are allowed to be ommited, are only really allowed
                #           becuase their value will is defined initially in tables.use_default_for_exclusion_list_items
                if($missing_columns.count -gt 0){

                    # there value is added to the hashtable defined by the user when command is involed
                    foreach($column in $my_path_table.table.use_default_for_exclusion_list_items.keys){
                        $fromSender.this_data.Add($column,$my_path_table.table.use_default_for_exclusion_list_items.$column)
                    }
                }

                # 2.0)  Evaluating Null Parameter Values:
                #       Not all parameter values submitted at invocation need to be given a value. This adds flexability to the data that
                #       might require it for use in future cases

                # step 2.1) the values from the user's this_data are evalutes against the list of values in null_values_list, anything that matches any
                #           of those items is considered to be a null entry
                $null_values_list = @($null,"",' ')
                $null_columns_list = @()
                foreach($entry_key in $fromSender.this_data.keys){
                    if($null_values_list -contains ( ($fromSender.this_data).$entry_key )){
                        $null_columns_list += $entry_key
                    }
                }

                # step 2.1) display information about what,if any, user provided properties are null
                $null_values_used       = [bool]
                $null_columns_string    = [string]
                if($null_columns_list.count -ne 0){
                    $null_columns_string = $null_columns_list -join "`n"
                    $null_values_used  = $true
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "the following user provided properties are null:`n$null_columns_string"
                }else{
                    $null_values_used  = $false
                    $show_message_params.message_type   = 'info'
                    $show_message_params.message        = "the update command proporties does not contain any null values"
                }
                #display feedback
                Show-Message @show_message_params

                # 2.2)  in the event that there are any null values used, the exception by checking the table.column_list.$column is_null property value
                $columns_that_cannot_be_null = @()
                if($null_values_used){
                    foreach($column in $my_path_table.table.column_list.keys){
                        $is_null = $my_path_table.table.column_list.$column.is_null

                        # values in columns_that_cannot_be_null are going to trigger the exception since they are not allowed to be null
                        if(-not($is_null)){
                            if($null_columns_list -contains $column){
                               $columns_that_cannot_be_null += $column
                            }
                        }
                    }
                }

                # 2.3) exception will be raised in the event that any null value that is not allowed to be null is null
                $raise_exception_invalid_nulls = [bool]
                if(-not($columns_that_cannot_be_null).count -eq 0){
                    $raise_exception_invalid_nulls  = $true
                    $show_message_params.message_type   = 'failed'
                    $show_message_params.message        = "a property provided is not allowed to be null.."
                }else{
                    $raise_exception_invalid_nulls  = $false
                    $show_message_params.message_type   = 'success'
                    $show_message_params.message        = "update request uses proper nullable values..."
                }
                # display feedback
                Show-Message @show_message_params
                if($raise_exception_invalid_nulls){
                    return
                }
               
                # 2.4) values in the insert statement that are null, are only really allowed to be null given the defined values in table.null_exception_list
                foreach($property_with_exception in $my_path_table.table.null_exception_list){

                    # each of the user's input values is checked against the defined null_exception to see if they even have a defined constraint set
                    foreach($user_data_column in $fromSender.this_data.Keys){

                        # any column that does have a matching null_exception_list defined contraint is evaluated
                        $input_dependant        = [bool]
                        $under_some_condition   = [bool]


                        if(($user_data_column -match "$($property_with_exception.Keys)") -and ($null_values_list -contains $fromSender.this_data.$user_data_column)){
                            $under_some_condition   = $my_path_table.table.null_exception_list.$user_data_column.under_some_condition
                           
                            # under_some_condition is what defines a null entry as having applicable null constraints to evalute
                            # if its false, doesn't matter if inpute_dependant is true or false, that property does can be null without having conditions
                            # to evaluate against
                            $has_null_constraints_to_evaluate = [bool]
                            if($under_some_condition -eq $true){
                                $has_null_constraints_to_evaluate = $true
                                $show_message_params.message_type   = 'info'
                                $show_message_params.message        = "the user property '$user_data_column' can be null under certain conditions.."
                            }
                            if($under_some_condition -eq $false){
                                $has_null_constraints_to_evaluate = $false
                                $show_message_params.message_type   = 'info'
                                $show_message_params.message        = "the user property '$user_data_column' can be null without a conditions check..."
                            }
                            # display feedback
                            Show-Message @show_message_params

                            # input_dependant; when true means that a property can only be null under the conditions defined for that property in 
                            # input_dependant table
                            $input_dependant = $my_path_table.table.null_exception_list.$user_data_column.input_dependant
                            if($has_null_constraints_to_evaluate){

                                # if it is input dependant, we need to evaluate those properties against the dependency table
                                if($input_dependant){
                                    $passed_dependency_check = [bool]
                                    $valid_dependecy_conditon_found = [bool]
                                    if(@($my_path_table.table.input_dependant_table.keys) -contains $user_data_column){
                                        $valid_dependecy_conditon_found = $true
                                        $show_message_params.message_type   = 'info'
                                        $show_message_params.message        = "the user property '$user_data_column' has a defined dependecy condition..."
                                    }else{
                                        $valid_dependecy_conditon_found = $false
                                        $show_message_params.message_type   = 'failed'
                                        $show_message_params.message        = "the user property '$user_data_column' does not have a defined dependecy condition..."
                                    }
                                    #display feedback
                                    Show-Message @show_message_params
                                    if((-not$valid_dependecy_conditon_found)){
                                        return
                                    }
                                }

                                # use the key of the condition to see what the value in the input needs to be
                                $dependent_on_this_property = ($my_path_table.table.input_dependant_table.($user_data_column).keys)
                                $this_value                 = ($my_path_table.table.input_dependant_table.($user_data_column).values)
                                if($fromSender.this_data."$($dependent_on_this_property)" -eq  $($this_value)){
                                    $passed_dependency_check = $true
                                    $show_message_params.message_type   = 'success'
                                    $show_message_params.message        = "the property '$user_data_column' passed it's dependency check"
                                }else{
                                    $passed_dependency_check = $false
                                    $show_message_params.message_type   = 'failed'
                                    $show_message_params.message        = "the property '$user_data_column' failed it's dependency check"
                                }
                                # display feedback
                                Show-Message @show_message_params

                                if(-not($passed_dependency_check)){
                                    $show_message_params.message_type = "info"
                                    $show_message_params.message      = "'$user_data_column' can only be null when '$dependent_on_this_property' is '$this_value'"
                                    # display feedback
                                    Show-Message @show_message_params
                                    return
                                }
                            }
                        }
                    }
                }

                # step 3.0) Table Identity:
                #           Each table can be defined with or without a identity property, the identity property is how each entry get auto enumerated on insert.
                $using_indentity_property = [bool]
                if($my_path_table.table.identity_properties.is_set){
                    $using_indentity_property = $true
                    $show_message_params.message_type   = "info"
                    $show_message_params.message        = "'$($fromSender.this_file)' uses an identity property..."
                }else{
                    $using_indentity_property = $false
                    $show_message_params.message_type   = "info"
                    $show_message_params.message        = "'$($fromSender.this_file)' does not use an identity property..."       

                }
                # display feedback
                Show-Message @show_message_params

                # if the table is using an identity property, the identity property defined will be used
                if($using_indentity_property){
                    $my_identity = $my_path_table.table.identity_properties.is
                    $it_is_empty = [bool]

                    # if there is no data in your table, then it is defined to be empty
                    if($null -match ($my_data.$my_identity)){
                        $it_is_empty = $true
                    }else{
                        $it_is_empty = $false
                    }

                    # if the data table is not empty, then whatever is the last entry, will be used to enumerate from
                    # given the defined increment by value. if the data is empty, it will increment from the seed value
                    $starting_at = [int]
                    
                    if($it_is_empty){
                        [int]$starting_at = [int]$($my_path_table.table.identity_properties.with_seed)
                    }else{
                        [int]$starting_at = ([int]($my_data | Select-Object -Property $my_identity -Last 1).$my_identity)
                    }
                    $fromSender.this_data.$my_identity = ($starting_at + $($my_path_table.table.identity_properties.and_increment))
                }
            }
            # -> additional file definition can be added here <-
            default{
                $is_valid_type                      = $false
                $show_message_params.message_type   = 'failed'
                $show_message_params.message        = "the file '$($fromSender.this_file)' is of a type '$($my_path_table.type)', which is undefined"
            }
        }

        if(-not($is_valid_type)){
            #display feedback
            Show-Message @show_message_params
            return
        }


        try{
            (([array]$my_data + (ConvertFrom-Hashtable -MyHashtable $fromSender.this_data))  | Select-Object $desiredOrder  | ConvertTo-Csv -NoTypeInformation)  | Out-File $my_path_table.path -ErrorAction Stop
            $show_message_params.message_type   = 'success'
            $show_message_params.message        = "insert operation complete"
        }catch{
            $show_message_params.message_type   = 'failed'
            $show_message_params.message        = "insert operation failed"
        }
        # display feedback
        Show-Message @show_message_params
    }
    [psobject]GetChecklistforThisHost([hashtable]$fromSender){
        $method_name        = "GetChecklistforThisHost"
        $output_msg         = $null
        $is_valid_source    = [bool]
        $separator          = $this.Dynamic.Settings.Separator
        $my_properties = $this.GetProperty('*')
        switch($fromSender.from_source){
            'psstig_parent_path'{
                $is_valid_source = $true
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "the source you provided '$($fromSender.from_source)' is valid "
                    write-host $output_msg -ForegroundColor Cyan
                }
            }
            'stig_parent_path'{
                $is_valid_source = $true
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "the source you provided '$($fromSender.from_source)' is valid "
                    write-host $output_msg -ForegroundColor Cyan
                }
            }
            default{
                # this will handle invalid sources provided
                $is_valid_source = $false
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "the source you provided '$($fromSender.from_source)' is not defined "
                    write-host $output_msg -ForegroundColor Red
                }
            }
        }
        $matched_checklist_object = $null
        if($is_valid_source){
            $collection_name_tagged     = "$($fromSender.collection_name)-STIGS"
            $collection_checklist_path  = "$($my_properties.$($fromSender.from_source))$($separator)$($collection_name_tagged)$($separator)CHECKLISTS$($separator)"

            $collection_checklist_parsed_namelists = @()
            $my_collection_checklist = Get-ChildItem -Path $collection_checklist_path
            $my_collection_checklist | ForEach-Object{
                $collection_checklist_parsed_namelists += (($_.BaseName -split ('_'))[0])
            }
            $collection_checklist_parsed_namelists_edited  =  $collection_checklist_parsed_namelists -replace ('-','\')

            # step through the edited checklists names
            foreach($checklist in $collection_checklist_parsed_namelists_edited){

                # see if the hostname provided matches anything
                if($fromsender.host_name -eq $checklist){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = '[{0}]:: {1}' -f
                        $method_name,
                        "the hostname provided '$($fromSender.host_name)' matches up to a checklist file..."
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    $checklist_name_editedback  = $checklist -replace ('\\','-')
                    $rebuilt_checklist_name = "$($checklist_name_editedback)_$($fromSender.collection_name)"
                    # if there is a match, look in the collection checklist object
                    # and see if it matches up to anything
                    foreach($checklist_file in $my_collection_checklist){
                        $matched_checklist_object = $checklist_file | Select-Object -Property *|Where-Object {$_.BaseName -eq $rebuilt_checklist_name}
                        if($null -ne $matched_checklist_object ){
                            break
                        }
                    }
                }
            }

            if($null -ne $matched_checklist_object){
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = '[{0}]:: {1}' -f
                    $method_name,
                    "found a check list for the host name provided '$($fromSender.host_name)' in this collection '$($fromSender.collection_name)'"
                    Write-Host $output_msg -ForegroundColor Cyan
                }
 
            }else{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = '[{0}]:: {1}' -f
                    $method_name,
                    "did not find any checklist associated with the hostname you provided '$($fromSender.host_name)' in this collection '$($fromSender.collection_name)'"
                    Write-Host $output_msg -ForegroundColor Red
                }
 
            }
        }
        return $matched_checklist_object
    }
    # this method creaated the folders inside the collection folder
    [void]CreateCollectionChildred([hashtable]$fromSender){
        $method_name    = "CreateCollectionChildred"
        $output_msg     = $null
        $separator      = ($this.Dynamic.Settings.Separator)

        $checklists_path    = "$($fromsender.collection_path)$($separator)CHECKLISTS"
        $documentation_path = "$($fromsender.collection_path)$($separator)DOCUMENTATION"
        $report_path        = "$($fromsender.collection_path)$($separator)REPORTS"

        New-Item -Path $checklists_path -ItemType "Directory"
        New-Item -Path $documentation_path -ItemType "Directory"
        New-Item -Path $report_path -ItemType "Directory"

        $output_msg = "[{0}]:: {1}" -f
        $method_name,
        "container folders created"
        Write-Host $output_msg -ForegroundColor Cyan

    }
    # this method removes a collection
    [void]RemoveACollection([hashtable]$fromSender){
        $method_name    = "RemoveACollection"
        $output_msg     = $null

        # all collections created get tagged with the following for their folder name
        # makes it easy to know wha the folder contents are about if youre just looking at it
        # in the file explorer
        $tagged_collection_name = "{0}-STIGS" -f $fromsender.collection_name

        if($this.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $method_name,
            "tagging the collection name you provided, the name of your collection is '$($tagged_collection_name)'"
            Write-Host $output_msg -ForegroundColor Cyan
        }

        # creating a checklist container
        $my_properties              = $this.GetProperty('*')
        $separator                  = ($this.Dynamic.Settings.Separator)
        $my_collection_path         = "$($my_properties.psstig_parent_path)$($separator)$($tagged_collection_name)"
        $my_local_collection_path   = "$($my_properties.stig_parent_path)$($separator)$($tagged_collection_name)"

        switch($fromsender.collection_type){
            'local'{
                if(test-path -path $my_local_collection_path){
                    if($fromsender.withComfirmation){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "You are about to remove collection '$($tagged_collection_name)' from location '$($my_properties.stig_parent_path)', are you sure you want to do this?"
                        Write-Host $output_msg -ForegroundColor Red
                        $user_input = read-host -Prompt "Enter 'Y' to continue, or 'N' to cancel"
           
                        if($user_input -eq "Y"){
                            Remove-Item -Path $my_local_collection_path -force
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "collection removed"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                        if($user_input -eq "N"){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "request cancelled"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                    }else{
                        Remove-Item -Path $my_local_collection_path -force
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "collection removed"
                        Write-Host $output_msg -ForegroundColor Yellow
                    }

                }else{
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is no collection by the name '$($fromsender.collection_name)' at the location '$($my_properties.stig_parent_path)'"
                    Write-Host $output_msg -ForegroundColor Red
                }

            }
            'remote'{
                if(test-path -path $my_collection_path){
                    if($fromsender.withComfirmation){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "You are about to remove collection '$($tagged_collection_name)' from location '$($my_properties.psstig_parent_path)', are you sure you want to do this?"
                        Write-Host $output_msg -ForegroundColor Red
                        $user_input = read-host -Prompt "Enter 'Y' to continue, or 'N' to cancel"
           
                        if($user_input -eq "Y"){
                            Remove-Item -Path $my_collection_path -force
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "collection removed"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                        if($user_input -eq "N"){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "request cancelled"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                    }else{
                        Remove-Item -Path $my_collection_path -force
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "collection removed"
                        Write-Host $output_msg -ForegroundColor Yellow
                    }

                }else{
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is no collection by the name '$($fromsender.collection_name)' at the location '$($my_properties.psstig_parent_path)'"
                    Write-Host $output_msg -ForegroundColor Red
                }

            }

            'local_and_remote'{
                if(test-path -path $my_collection_path){
                    if($fromsender.withComfirmation){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "You are about to remove collection '$($tagged_collection_name)' from location '$($my_properties.psstig_parent_path)', are you sure you want to do this?"
                        Write-Host $output_msg -ForegroundColor Red
                        $user_input = read-host -Prompt "Enter 'Y' to continue, or 'N' to cancel"
           
                        if($user_input -eq "Y"){
                            Remove-Item -Path $my_collection_path -force
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "collection removed"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                        if($user_input -eq "N"){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "request cancelled"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                    }else{
                        Remove-Item -Path $my_collection_path -force
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "collection removed"
                        Write-Host $output_msg -ForegroundColor Yellow
                    }

                }else{
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is no collection by the name '$($fromsender.collection_name)' at the location '$($my_properties.psstig_parent_path)'"
                    Write-Host $output_msg -ForegroundColor Red
                }


                if(test-path -path $my_local_collection_path ){
                    if($fromsender.withComfirmation){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "You are about to remove collection '$($tagged_collection_name)' from location '$($my_properties.stig_parent_path)', are you sure you want to do this?"
                        Write-Host $output_msg -ForegroundColor Red
                        $user_input = read-host -Prompt "Enter 'Y' to continue, or 'N' to cancel"
           
                        if($user_input -eq "Y"){
                            Remove-Item -Path $my_local_collection_path -force
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "collection removed"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                        if($user_input -eq "N"){
                            $output_msg = "[{0}]:: {1}" -f
                            $method_name,
                            "request cancelled"
                            Write-Host $output_msg -ForegroundColor Yellow
                        }
                    }else{
                        Remove-Item -Path $my_local_collection_path -force
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "collection removed"
                        Write-Host $output_msg -ForegroundColor Yellow
                    }

                }else{
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is no collection by the name '$($fromsender.collection_name)' at the location '$($my_properties.stig_parent_path)'"
                    Write-Host $output_msg -ForegroundColor Red
                }

            }
            default{
                $collectiontypeList = @(
                    'local','remote','local_and_remote'
                )
                $collectiontypeList = $collectiontypeList -join "`n"
                $output_msg = "[{0}]:: {1}" -f
                $method_name,
                "the collection type you provided '$($fromsender.collection_type)' is not defined, you can provide one of the following types of collections `n$($collectiontypeList)`n "
                Write-Host $output_msg -ForegroundColor Red
            }
        }
    }
    # this method creates a collection
    [void]CreateACollection([hashtable]$Fromsender){
       
        $method_name    = "CreateCollection"
        $output_msg     = $null

        # all collections created get tagged with the following for their folder name
        # makes it easy to know wha the folder contents are about if youre just looking at it
        # in the file explorer
        $tagged_collection_name = "{0}-STIGS" -f $fromsender.collection_name

        if($this.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $method_name,
            "tagging the collection name you provided, the name of your collection is '$($tagged_collection_name)'"
            Write-Host $output_msg -ForegroundColor Cyan
        }

        # creating a checklist container
        $my_properties              = $this.GetProperty('*')
        $separator                  = ($this.Dynamic.Settings.Separator)
        $my_collection_path         = "$($my_properties.psstig_parent_path)$($separator)$($tagged_collection_name)"
        $my_local_collection_path   = "$($my_properties.stig_parent_path)$($separator)$($tagged_collection_name)"

       

        # when you only want to create a local collection, we dont care if the PSSTISDATA collection is there or not
        $local_collection_creation_succeeded    = [bool]
        $collection_creation_succeeded          = [bool]

        if($fromsender.only_create_local_collection -eq $true){
            if(-not(Test-Path -path $my_local_collection_path)){
                # if the local collection is not there, we create it
                New-Item -Path $my_local_collection_path -ItemType "Directory" | Out-Null
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "created the collection you requested at this location: '$($my_local_collection_path)'"
                    Write-Host $output_msg -ForegroundColor Cyan
                }
                $local_collection_creation_succeeded = $true
                if($local_collection_creation_succeeded){
                    $this.AddXMLDataToCollection(@{
                        collection_path = $my_local_collection_path
                        from_this_xml_data = $fromsender.from_this_xml_data
                    })
                    $this.CreateCollectionChildred(@{'collection_path' = $my_local_collection_path})
                }
            }else{
                # if there is already a local collection at the local path, then the collection cannot be created
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is already a collection named '$($tagged_collection_name)' at this location '$($my_properties.stig_parent_path)'"
                }
                Write-Host $output_msg -ForegroundColor Red
                $local_collection_creation_succeeded = $false
            }
        }else{
            # if only_create_local_collection is false, we want to create the remote location AND the local collection
            # when this is the case, the remote collection creation need to be successful in order for the local collection to be created
            if(-not(Test-Path -path $my_collection_path)){
                # only create the remote collection if there isnt already on there with the same name
                New-Item -Path $my_collection_path -ItemType "Directory" | Out-Null
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "created the collection you requested at this location: '$($my_collection_path)'"
                    Write-Host $output_msg -ForegroundColor Cyan
                }
                $collection_creation_succeeded = $true
                if($collection_creation_succeeded){
                    $this.AddXMLDataToCollection(@{
                        collection_path = $my_collection_path
                        from_this_xml_data = $fromsender.from_this_xml_data
                    })
                    $this.CreateCollectionChildred(@{'collection_path' = $my_collection_path})
                }
            }else{
                # if there is already a collection at the given location, then the collection cannot be created
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "there is already a collection named '$($tagged_collection_name)' at this location '$($my_properties.psstig_parent_path)'"
                }
                Write-Host $output_msg -ForegroundColor Red
                $collection_creation_succeeded = $false
            }

            # the collection creation is considered to have succeeded if you can create the collection a.k.a the folder in the given location
            if($collection_creation_succeeded){
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "collection creation is complete..."
                    Write-Host $output_msg -ForegroundColor Cyan
                }
            }else{
                # the collection creation is considered to have failed if you tried to create one and there way one already there of the same name
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $method_name,
                    "collection creation failed..."
                    Write-Host $output_msg -ForegroundColor Red
                }  
            }

            if($collection_creation_succeeded){
                # only if ther remote collection passed can you create a local collection
                if(-not(Test-Path -path $my_local_collection_path)){
                    # if the local collection is not there, we create it
                    New-Item -Path $my_local_collection_path -ItemType "Directory" | Out-Null
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "created the local collection you requested at this location: '$($my_local_collection_path)'"
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    $local_collection_creation_succeeded = $true
                    if($local_collection_creation_succeeded){
                        $this.AddXMLDataToCollection(@{
                            collection_path = $my_local_collection_path
                            from_this_xml_data = $fromsender.from_this_xml_data
                        })
                        $this.CreateCollectionChildred(@{'collection_path' = $my_local_collection_path})
                    }
                }else{
                    # if there is already a local collection at the local path, then the collection cannot be created
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "there is already a local collection named '$($tagged_collection_name)' at this location '$($my_properties.stig_parent_path)'"
                    }
                    Write-Host $output_msg -ForegroundColor Red
                    $local_collection_creation_succeeded = $false
                }

                if($local_collection_creation_succeeded){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "local collection creation is complete..."
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                }else{
                    # the local collection creation is considered to have failed if you tried to create one and there way one already there of the same name
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $method_name,
                        "local collection creation failed..."
                        Write-Host $output_msg -ForegroundColor Red
                    }  
                }
            }else{
                $output_msg = "[{0}]:: {1}" -f
                $method_name,
                "local collection creation is only able to be attempted when the remote collection creation is successful..."
                Write-Host $output_msg -ForegroundColor Red
            }

        }
    }
    # this method creates reports
    [void]GetReport([hashtable]$fromSender){
        $function_name = "GetReport"
        $fromSender.add("report_name",$fromSender.check_listName)
        $dateReport_generated = (get-date).ToString('yyyyMMddHHmmss')
        $method_report_name = "{0}_{1}" -f $dateReport_generated,$fromSender.report_name

        $this.SyncCheckListChanged($fromSender.check_listName,'.\STIGVIEWERDATA')
        $MyData = $this.GetCheckList($fromSender.check_listName,$fromSender.from_source)
       
        #TODO:: there needs to be a way to create reports, and store them for future use
        #       in order to implement this, the read/write through cache needs to work a bit better
        $MyconvertedData = $null
        $validReport = $true
        if($validReport -eq $true){
            if($fromSender.report_name -match $fromSender.report_name){
                # filter out these options
                $MySubData = $MyData.stigs.rules | Select-Object -Property * -ExcludeProperty @('target_key','stig_ref','comments','finding_details','fix_text','check_content','group_title','legacy_ids','check_content_ref','discussion','ccis','group_tree')
                $MySubData | Select-Object -property @('group_id','
                    severity',
                    'status'
                    'rule_version',
                    'weight',
                    'rule_title'
                    'calssification',
                    'false_positive',
                    'false_negative',
                    'documentable',
                    'security_override_guidance',
                    'potential_impacts',
                    'third_party_tols',
                    'ia_controls',
                    'responsibility',
                    'mitigations',
                    'reference_identifier')

                    $MyconvertedData = $MySubData | ConvertTo-Csv -Delimiter "," -NoTypeInformation
            }
        }
       
        $MyconvertedData | Out-File  "$(Get-ScriptPath)$($this.Dynamic.settings.Separator)REPORTS$($this.Dynamic.settings.Separator)$($method_report_name).csv"
        if($this.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "report created, report located at $(Get-ScriptPath)$($this.Dynamic.settings.Separator)REPORTS$($this.Dynamic.settings.Separator)$($method_report_name).csv"
            Write-host $output_msg -ForegroundColor Cyan
        }
    }
    # this method forces the stigviewer to restart if its running
    [void]RestartStigViewer([hashtable]$fromSender){
        $method_name            = "RestartStigViewer"
        $outout_msg             = $null
        $is_stig_viewer_running = [bool]

        if(Get-Process -Name "*STIG*") {
            $is_stig_viewer_running = $true
        }else{
            $is_stig_viewer_running = $false
        }

        # if the stig viewer is running, it will stop and start backup
        if($is_stig_viewer_running){
            (Get-Process -Name "*STIG*") | Stop-Process -Force
            Start-Process -FilePath "$($this.Enviornmental.Settings.Stig_Viewer_path)\$($fromsender.program_name)"
        }else{
            # if its not running, then you have an option here
            # if you pass in true it will start it up
            if($fromSender.unless_not_currently_running){
                Start-Process -FilePath "$($this.Enviornmental.Settings.Stig_Viewer_path)\$($fromsender.program_name)"
            }else{
                $outout_msg = "[{0}]:: {1}" -f
                $method_name,
                "'$($fromsender.program_name)' is currently not running"
                Write-Host $outout_msg -ForegroundColor Yellow
            }
        }
    }

    [psobject]UpdateChecklistForThisHost([hashtable]$fromSender){

        $my_checklist_object = $this.GetChecklistforThisHost(@{
            host_name           = $fromSender.ForHostName
            from_source         = $fromSender.FromThisSource
            collection_name     = $FromSender.FromThisCollection
        })

        $my_checklist_data = $this.SelectDataFromThisChecklistFile(@{
            my_checklist_file_object    = $my_checklist_object
            operator                    = $fromSender.Operator
            WhereThis                   = $fromSender.Where
            isThis                      = $fromSender.IsThis
         
        })

       return  $my_checklist_data
    }
    [psobject]SelectFromCheckThisList([hashtable]$fromSender){

        $my_checklist_object = $this.GetChecklistforThisHost(@{
            host_name           = $fromSender.ForHostName
            from_source         = $fromSender.FromThisSource
            collection_name     = $FromSender.FromThisCollection
        })

        $my_checklist_data = $this.SelectDataFromThisChecklistFile(@{
            my_checklist_file_object    = $my_checklist_object
            operator                    = $fromSender.Operator
            WhereThis                   = $fromSender.Where
            isThis                      = $fromSender.IsThis
         
        })

       return  $my_checklist_data
    }
    [psobject]SelectDataFromThisChecklistFile([hashtable]$Fromsender){
        $function_name      = "SelectDataFromThisChecklistFile"
        $output_msg         = $null
        $MyData             = Get-Content -path ($fromsender.my_checklist_file_object).FullName  -raw| ConvertFrom-Json
        $filtered_data      = @()

        $operation_invalid  = $false
        switch($Fromsender.operator){
            'none'{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg ="[{0}]:: {1}" -f
                    $function_name,
                    "no filters selected, whatever you have set in 'WhereThis', and 'isThis' are not considered in your search"
               
                }
                foreach($finding in $MyData.stigs.Rules){
                    $filtered_data += $finding | Select-Object -Property *
                }
            }
            'eq'{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
               
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach($f_itemItem in $_) {
                        $filtered_data += $f_itemItem | Select-Object -Property * | Where-Object {$_.($Fromsender.WhereThis) -eq ($Fromsender.isThis)}
                    }
                }
            }
            'ne'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
       
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -ne ($Fromsender.isThis))
                    }
                }
            }
            'gt'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
               
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -gt ($Fromsender.isThis))
                    }
                }
            }
            'lt'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -lt ($Fromsender.isThis))
                    }
                }
            }
            'match'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
                 
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -match ($Fromsender.isThis))
                    }
                }
            }
            'notmatch'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
             
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -notmatch ($Fromsender.isThis))
                    }
                }
            }
            'contains'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
             
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -contains ($Fromsender.isThis))
                    }
                }
            }
            'notcontains'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
               
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -notcontains ($Fromsender.isThis))
                    }
                }
            }
            'like'
            {
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "where '$($fromsender.WhereThis)' is '$($fromsender.Operator)' to '$($fromsender.isThis)'"
             
                }
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem  | Select-Object -Property * | Where-Object ($_.($Fromsender.WhereThis) -like ($Fromsender.isThis))
                    }
                }
            }
            default{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}" -f
                    $function_name,
                    "unknown operator provided. '$($Fromsender.operator)' is not defined"
                    Write-Host $output_msg -ForegroundColor red
                    $operation_invalid = $true
                }
            }
        }
        if($operation_invalid){
            $filtered_data = $null
        }else{
            Write-Host $output_msg -ForegroundColor Yellow
        }
        return $filtered_data
    }
    [psobject]SelectFromCheckList([hashtable]$Fromsender){
        $function_name = "SelectFromCheckList"

        $MyData             = $this.GetCheckList($Fromsender.FromThisCheckList ,$Fromsender.FromThisSource)
        $filtered_data      = @()
        $operation_invalid  = $false
        switch($Fromsender.operator){
            'none'{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg ="[{0}]:: {1}"
                    $function_name,
                    "no filters selected, whatever you have set in 'WhereThis', and 'isThis' are not considered in your search"
                    write-host $output_msg -ForegroundColor Cyan
                }
                foreach($finding in $MyData.stigs.Rules){
                    $filtered_data += $finding | Select-Object -Property *
                }
            }
            'eq'{
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $f_itemItem | Select-Object -Property * | Where-Object {$_.$($Fromsender.WhereThis) -eq "$($Fromsender.isThis)"}
                    }
                }
            }
            'ne'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -ne $Fromsender.isThis)
                    }
                }
            }
            'gt'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -gt $Fromsender.isThis)
                    }
                }
            }
            'lt'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -lt $Fromsender.isThis)
                    }
                }
            }
            'match'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -match $Fromsender.isThis)
                    }
                }
            }
            'notmatch'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -notmatch $Fromsender.isThis)
                    }
                }
            }
            'contains'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -contains $Fromsender.isThis)
                    }
                }
            }
            'notcontains'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -notcontains $Fromsender.isThis)
                    }
                }
            }
            'like'
            {
                $MyData.stigs.Rules | ForEach-Object{
                    foreach ($f_itemItem in $_) {
                        $filtered_data += $finding  | Select-Object -Property * | Where-Object ($_.$Fromsender.WhereThis -like $Fromsender.isThis)
                    }
                }
            }
            default{
                if($this.DevSettings.DEBUG_ON){
                    $output_msg = "[{0}]:: {1}"
                    $function_name,
                    "unknown operator provided. '$($Fromsender.operator)' is not defined"
                    Write-Host $output_msg -ForegroundColor red
                    $operation_invalid = $true
                }
            }
        }
        if($operation_invalid){
            $filtered_data = $null
        }
        return $filtered_data
    }
    [void]UpdateMyCheckList([hashtable]$Fromsender){
        $function_name = 'UpdateMyCheckList'
        $internal_FromSenderData = @{
            checklist_name          = $Fromsender.checklist_name
            from_source             = "$($Fromsender.from_source)"
            finding_id              = $Fromsender.finding_id
            withComfirmation        = $Fromsender.withComfirmation
            withAutoRefresh         = $Fromsender.withAutoRefresh
            userproperties_table    = $Fromsender.userproperties_table
        }
        $findingIds_list = @()
        $MyData = $this.GetCheckList($Fromsender.checklist_name,$Fromsender.from_source)
        $findingIds_list += $MyData.stigs.rules.group_id

        $user_intput = $null
        if($Fromsender.finding_id -eq '*'){
            $output_msg = "{0}:: {1}" -f
                $function_name,
                "you have selected to update all $($findingIds_list.count) findings.`n      Enter 'Y' to confirm this option`n      Enter 'N' to cancel`n"
            $user_intput = Read-Host $output_msg

            if($user_intput -eq 'Y'){
                foreach($fid in $findingIds_list){
                    $internal_FromSenderData.finding_id = $fid
                    $this.UpdateCheckList($internal_FromSenderData)
                }
            }
            if($user_intput -eq 'N'){
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "canceled update..."
                Write-Host $output_msg -ForegroundColor Yellow
            }

        }else{
            $this.UpdateCheckList($internal_FromSenderData)
        }
    }
    [void]ApplyCommentsTemplateToFinding([hashtable]$Fromsender){
        $function_name = 'ApplyCommentsTemplateToFinding'
        #get the template from templates
       
        $MyTemplateString = [string]
        if(test-path -path $("$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)templates$($this.Dynamic.Settings.Separator)$($Fromsender.template_name)")){

            $MyTemplateString = (Get-Content -Path $("$(Get-ScriptPath)$($this.Dynamic.Settings.Separator)templates$($this.Dynamic.Settings.Separator)$($Fromsender.template_name)") -RAW )
        }
        $internal_FromSenderData = @{
            checklist_name          = $Fromsender.checklist_name
            from_source             = $Fromsender.from_source
            finding_id              = $Fromsender.finding_id
            withComfirmation        = $Fromsender.withComfirmation
            withAutoRefresh         = $Fromsender.withAutoRefresh
            userproperties_table    = @{
                comments = "$($MyTemplateString )"
            }
        }

        $findingIds_list = @()
        $MyData = $this.GetCheckList($Fromsender.checklist_name,$Fromsender.from_source)
        $findingIds_list += $MyData.stigs.rules.group_id

        $user_intput = $null
        if($Fromsender.finding_id -eq '*'){
            $output_msg = "{0}:: {1}" -f
                $function_name,
                "you have selected to update all [$($findingIds_list.count)] finding comment text from your template '$($Fromsender.template_name)'`n     Enter 'Y' to confirm this option`n      Enter 'N' to cancel"
            $user_intput = Read-Host $output_msg

            if($user_intput -eq 'Y'){
                foreach($fid in $findingIds_list){
                    $internal_FromSenderData.finding_id = $fid
                    $this.UpdateCheckList($internal_FromSenderData)
                }
            }
            if($user_intput -eq 'N'){
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "canceled update..."
                Write-Host $output_msg -ForegroundColor Yellow
            }

        }else{
            $this.UpdateCheckList($internal_FromSenderData)
        }
    }
    [void]UpdateCheckList([hashtable]$fromsender_params){
       
        $function_name = 'UpdateCheckList'
        # first off, go ahead and read in the data
        $MyDataSource = $this.GetCheckList(($fromsender_params.checklist_name),($fromsender_params.from_source))

        # you can only upade things on this list
        $updateable_properties_List    = @(
            'status',
            'false_negatives',
            'overrides',
            'false_positives',
            'mitigations',
            'potential_impacts',
            'third_party_tools',
            'mitigation_control',
            'responsability',
            'security_override_guidance',
            'ia_controls',
            'comments',
            'finding_details'
        )

        # this is just a string version of the updatable list, to display in messages when needed
        $updatableListString = ($updateable_properties_List -split ",") -join "`n"
        $userprovided_keys = $updateable_properties_List | Where-Object { $fromsender_params.userproperties_table.ContainsKey($_) }

        $userprovided_keys_none = $false
        if($userprovided_keys.count -eq 0){
            $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "make sure you provide something to update into this method, you can use any of the following `n$updatableListString"
            Write-Host $output_msg -ForegroundColor Red
            $userprovided_keys_none = $true
        }
        # (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        # only if something was provided to you want to do an update
        if($userprovided_keys_none -eq $false){

            # provide feed back for looking for the key
            if($this.DevSettings){
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "looking for the finding given your provided key, stand by..."
                Write-Host $output_msg -ForegroundColor Yellow
            }

            # by default we will assume that the ID is never valid right off the bat
            $valid_finding_ID_provided = $false

            # the main search is done with a key, so we need to make sure that the user provided a valid finding id
            # only when any valid key is found does the switch change to true from false
            foreach($finding in ($MyDataSource.stigs.rules)){
                if($finding.group_id -match $fromsender_params.finding_id){
                    $valid_finding_ID_provided = $true
                }
            }

            # this value will be true if the user provided a valid ID
            if($valid_finding_ID_provided){
                if($this.DevSettings){
                    $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the key you provided '$($fromsender_params.finding_id)' is  valid!"
                    Write-Host $output_msg -ForegroundColor Cyan
                }

                # loop on the findings
                $DateTimeCreated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                foreach($finding in ($MyDataSource.stigs.rules)){
                   
                    # only when you match up to a finding id, do the following
                    if($finding.group_id -match $fromsender_params.finding_id){

                        # user provided keys can vary in terms of how many updates are going to take place
                       
                        foreach($userKey in $userprovided_keys){

                            if($this.DevSettings){
                                $output_msg = "[{0}]:: {1}" -f
                                    $function_name,
                                    "headsup, updating '$($userKey)' with the value provided '$($fromsender_params.updatetable.$userKey)'"
                                Write-Host $output_msg -ForegroundColor Cyan
                            }

                            # only when the withComfirmation option is off, you'll not need to confirm
                            if($fromsender_params.withComfirmation -eq $false){
                                $finding.$userKey = $fromsender_params.userproperties_table.$userKey
                                $finding.updatedAt = $DateTimeCreated
                            }else{
                                $output_msg = "[{0}]:: {1}" -f
                                    $function_name,
                                    " the withComfirmation option is set to 'true', so you need to accept the change for '$($userKey)'...    `n Enter Y to accept, N to skip"
                                $user_input = read-host -Prompt $output_msg

                                if($user_input -eq 'Y'){
                                    $finding.$userKey = $fromsender_params.updatable.$userKey
                                    $finding.updatedAt = $DateTimeCreated
                                    Write-Host "  change for '$($userKey)' applied" -ForegroundColor Yellow
                                }
                                if($user_input -eq 'N'){
                                    $output_msg = "[{0}]:: {1}" -f
                                    $function_name,
                                    "  change for '$($userKey)' canceled"
                                    Write-Host $output_msg -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                }
            }
            else{
                if($this.DevSettings){
                    $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the key you provided '$($fromsender_params.finding_id)' is not valid, please provided a valid finding ID."
                    Write-Host $output_msg -ForegroundColor Red
                }
            }
        }

        if($this.DevSettings){
            $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "Update Complete..."
            Write-Host $output_msg -ForegroundColor Cyan
        }

        if($fromsender_params.withAutoRefresh){
            if($this.DevSettings){
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "the withAutoRefresh option is set to 'true', refreshing $()"
            Write-Host $output_msg -ForegroundColor Cyan        
            }
           
            Set-Content -Path "$($fromsender_params.from_source)$($this.Dynamic.Settings.Separator)CHECKLISTS$($this.Dynamic.Settings.Separator)$($fromsender_params.checklist_name).cklb"  -Value ($MyDataSource | ConvertTo-Json -Depth 5)
            $this.SyncCheckListChanged($fromsender_params.checklist_name,$fromsender_params.from_source)
        }else{
            Set-Content -Path "$($fromsender_params.from_source)$($this.Dynamic.Settings.Separator)CHECKLISTS$($this.Dynamic.Settings.Separator)$($fromsender_params.checklist_name).cklb"  -Value ($MyDataSource | ConvertTo-Json -Depth 5)
        }
    }
    [psobject]GetCheckList([string]$check_listName,[string]$FromSource){
        $function_name  = 'GetCheckList'
        $separator      = $this.Dynamic.settings.Separator
        $paths          = $this.GetProperty('*')
        $mycontent      = $false

         # given a source provided
         switch($FromSource){
            # copy the checklist modified in psstig over to stigviewer data
            ".$($separator)PSSTIGDATA"{

                # test first to make sure that there is something there to read
                if(Test-Path -path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                    $source_is_good = $true

                }else{
                    $source_is_good = $false
                }

                # only if the source is good, does the copy actually run
                if($source_is_good){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the source your provided '$($FromSource)' does contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    $mycontent = (Get-Content -Path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb") | ConvertFrom-Json
                }else{
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the source your provided '$($FromSource)' does not contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Red
                    }
                }

            }
            # copy the checklist modified in stigviewer over to psstig data
            ".$($separator)STIGVIEWERDATA"{

                # test first to make sure that there is something there to read
                if(Test-Path -path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                    $source_is_good = $true

                }else{
                    $source_is_good = $false
                }
                # only if the source is good, does the copy actually run
                if($source_is_good){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the source your provided '$($FromSource)' does contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    $mycontent = (Get-Content -Path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb") | ConvertFrom-Json
                }else{
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "the source your provided '$($FromSource)' does not contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Red
                    }
                }
            }
            default{
                $source_is_good = $false
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "the '$($FromSource)' is not defined, make sure you are providing either PSSTIGDATA, or STIGVIEWERDATA sources"
                Write-Host $output_msg -ForegroundColor Red
            }

        }
        return $mycontent    
    }
    [void]SyncCheckListChanged([string]$check_listName,[string]$FromSource){
        $function_name  = 'SyncCheckListChanged'
        #$FromSource     = '.\PSSTIGDATA'
        #$check_listName = 'SQL_DATABASE'
        $separator      = $this.Dynamic.settings.Separator
        $paths          = $this.GetProperty('*')

        # given a source provided
        switch($FromSource){
            # copy the checklist modified in psstig over to stigviewer data
            ".$($separator)PSSTIGDATA"{
                if(Test-Path -path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                    $source_is_good = $true

                }else{
                    $source_is_good = $false
                }

                # only if the source is good, does the copy actually run
                if($source_is_good){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "Syncing your change(s) over to 'stigviewer' from 'psstigdata'..."
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    if(Test-Path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                        Remove-Item -Path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"
                    }
                    $destination = "$($paths.stig_parent_path)$($separator)CHECKLISTS"
                    Copy-Item -Path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb" -Destination $destination
                }else{
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        " looks like the source you provided '$($FromSource)' does not contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Red
                    }
                }
            }
            # copy the checklist modified in stigviewer over to psstig data
            ".$($separator)STIGVIEWERDATA"{
                if(Test-Path -path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                    $source_is_good = $true

                }else{
                    $source_is_good = $false
                }
                # only do the copy if the source is valid
                if($source_is_good){
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "Syncing your change(s) over to 'psstigdata' from 'stigviewer'..."
                        Write-Host $output_msg -ForegroundColor Cyan
                    }
                    if(Test-Path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"){
                        Remove-Item -Path "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb"
                    }
                    $destination = "$($paths.psstig_parent_path)$($separator)CHECKLISTS$($separator)"
                    Copy-Item -Path "$($paths.stig_parent_path)$($separator)CHECKLISTS$($separator)$($check_listName).cklb" -Destination $destination
                }else{
                    if($this.DevSettings.DEBUG_ON){
                        $output_msg = "[{0}]:: {1}" -f
                        $function_name,
                        "looks like the source you provided '$($FromSource)' does not contain a checklist named '$($check_listName)'"
                        Write-Host $output_msg -ForegroundColor Red
                    }
                }
            }
            default{
                $output_msg = "[{0}]:: {1}" -f
                $function_name,
                "the '$($FromSource)' is not defined, make sure you are providing either PSSTIGDATA, or STIGVIEWERDATA sources"
                Write-Host $output_msg -ForegroundColor Red
            }
        }
    }
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
            cklb_version        = "$(($xml_rawdata.xml).Substring(9,1)).0"
            title               = $CheckList_title              # we can create this
            id                  = $CheckList_guid
            stigs               = @()
            active              = $true                        # test checklist set to false, but need to define somehwhere
            mode                = 1                            # check list has this as 2, but need to define somehwere
            has_path            = $false                         # checklist has set to true, but needs to be defined somewhere
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
            reference_identifier    = ""
            size                    = [int]
            rules                   = @()
        }
       
        $StigListItemTable.uuid                 = $Stig_guid
        $StigListItemTable.stig_name            = $xml_rawdata.Benchmark.title
        $StigListItemTable.display_name         = $xml_rawdata.Benchmark.group[0].rule.reference.subject
        $StigListItemTable.stig_id              = $xml_rawdata.Benchmark.id
        $StigListItemTable.realese_info         = $xml_rawdata.Benchmark.'plain-text'.'#text'[0]
        $StigListItemTable.reference_identifier = $xml_rawdata.Benchmark.group[0].rule.reference.identifier
        $StigListItemTable.size                 = $xml_rawdata.Benchmark.Group.count
       
        # starting at the group level
        $rule_id_value = ""
        foreach($group_finding in $xml_rawdata.Benchmark.Group){
            $DiscussionTable = $this.XMLParseOut_Discussion($group_finding.rule)
            if("$($group_finding.Rule.id)" -match '(SV-.*)(_rule)'){
                $rule_id_value = $matches[1]
            }
            $rule_item = @{
                uuid                        = $null
                stig_uuid                   = $Stig_guid
                group_id                    = ""
                group_id_src                = ""
                rule_id                     = ""
                rule_id_src                 = ""
                weight                      = ""
                classification              = "Unclassified"
                severity                    = ""
                rule_version                = ""
                group_title                 = ""
                rule_title                  = ""
                fix_text                    = ""
                false_positives             = ""
                false_negatives             = ""
                discussion                  = ""
                check_content               = ""
                reference_identifier        = ""
                documentable                = ""
                mitigations                 = ""
                potential_impacts           = ""
                third_party_tools           = ""
                mitigation_control         = ""
                responsability              = ""
                security_override_guidance = ""
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
            $DateTimeCreated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $rule_item.uuid                         = (New-Guid).Guid
            $rule_item.stig_uuid                    = $StigListItemTable.uuid
            $rule_item.group_id                     = $group_finding.id
            $rule_item.reference_identifier         = $StigListItemTable.reference_identifier
            $rule_item.rule_id                      = $rule_id_value
            $rule_item.rule_id_src                  = $group_finding.Rule.id
            $rule_item.weight                       = $group_finding.Rule.weight
            #$rule_item.classification               = "Unclassified"
            $rule_item.severity                     = $group_finding.Rule.severity
            $rule_item.rule_version                 = $group_finding.Rule.version
            $rule_item.rule_title                   = $group_finding.Rule.title
            $rule_item.group_title                  = $group_finding.RULE.title
            $rule_item.fix_text                     = $group_finding.Rule.fixtext.'#text'
            $rule_item.group_id_src                 = $group_finding.id
            $rule_item.false_positives              = ""
            $rule_item.false_negatives              = ""
            $rule_item.discussion                   = $DiscussionTable.VulnDiscussion
            $rule_item.check_content                = $group_finding.Rule.check.'check-content'
            $rule_item.documentable                 = if($DiscussionTable.Documentable -eq 'false'){'false'}else{'true'}
            $rule_item.mitigations                  = $DiscussionTable.mitigations
            $rule_item.potential_impacts            = ""
            $rule_item.third_party_tools            = ""
            $rule_item.mitigation_control           = ""
            $rule_item.responsability               = ""
            $rule_item.security_override_guidance   = $DiscussionTable.SeverityOverrideGuidance
            $rule_item.ia_controls                  = ""
            $rule_item.check_content_ref.href       = $group_finding.Rule.check.'check-content-ref'.href
            $rule_item.check_content_ref.Name       = $group_finding.Rule.check.'check-content-ref'.name
            $rule_item.legacy_ids                   = @($group_finding.Rule.ident.'#text'[0..1])
            $rule_item.ccis                         = @($group_finding.Rule.ident.'#text'[-1])
            $rule_item.group_tree                   += @{
                                                            id          = $group_finding.id
                                                            title       = $group_finding.title
                                                            description = "{0}GroupDescription{1}{0}{2}GroupDescription{1}"
                                                        }
            $rule_item.createdAt                    = $DateTimeCreated
            $rule_item.UpdateAt                     = $DateTimeCreated
            $rule_item.overrides                    = @{}
            $rule_item.comments                     = ""
            $rule_item.finding_details              = ""
           
            $rule_item.group_title
            $StigListItemTable.rules += $rule_item

        }

        $CheckListTemplate.stigs += $StigListItemTable
        return $CheckListTemplate
    }
    [psobject]GetCache(){
        $cache_file = $this.Cache.Settings.File
        $jsonObject = (Get-Content -Path $cache_file) | ConvertFrom-Json
        $hstashTable = $jsonObject | ForEach-Object { $_.PSObject.Properties } | ForEach-Object {
            @{ $_.Name = $_.Value }
        }
        return $hstashTable
    }
    # GetProperty returns all the properties set in the class
    [psobject]GetProperty([string]$PropertyName){

        # this setting here is set during the initial setup
        $using_default  = $this.Dynamic.Settings.use_default
        $path_type      = [string]

        if($using_default){$path_type = 'default'}else{$path_type = 'custom'}

        $MyObject = switch($PropertyName){
            "host_name"{
                # this property is set at initial setup
                $this.Dynamic.Settings.host_name
            }
            "setup_complete"{
                # this property is set at initial set up
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

        # when the cache doesnt exists it get created
        # or when you want to create a new one manually
        if(($this.Cache.settings.Exists -eq $false) -or ($NewCache)){
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
    PSSTIG([hashtable]$PathsConfiguration){
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
    [psobject]GetRawSTIGXMLData([string]$stig_xml_file){
        $function_name          = "GetRawSTIGXMLData"
        $my_stig_files          = $null
        [xml]$my_stig_rawdata   = $null
        $cache_exists           = [bool]

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
}

# this will initalize the module class for this module
Function Initialize-PSSTIG(
    [string]$WorkingRootDir,[string]$PathTo_StigViewerEXE,[bool]$UseDefaults,[string]$PSSTIGParentPath,[string]$STIGParentPath)
{
    $function_name = 'Initialize-PSSTIG'
    # when initializing, you set the working root with this function
    Set-Location -path $WorkingRootDir
    $PSSTIG = [PSSTIG]::new(
        @{
            use_defaults        = $UseDefaults
            psstig_parent_path  = $PSSTIGParentPath     #CHECK_LISTS folder contains your checklist file
            stig_parent_path    = $STIGParentPath       #CHECK_LISTS folder contains your checklist file
        }
    )
    $PSSTIG.Enviornmental.Settings.Stig_Viewer_path = $PathTo_StigViewerEXE
    # here we set up the stigviewer path
    $PSSTIG

    # part of the initalization process is to make sure that the parent directories for psstig_paren_path and sitg_parent_path
    # have a folder in them called CHECKLISTS

    if($PSSTIG.Enviornmental.Settings.PSStig.paths.custom.is_valid){
        $psstig_path = $PSSTIG.Enviornmental.Settings.PSStig.paths.custom.use
    }
    if($PSSTIG.Enviornmental.Settings.PSStig.paths.default.is_valid){
        $psstig_path = $PSSTIG.Enviornmental.Settings.PSStig.paths.default.use
    }

    if($PSSTIG.Enviornmental.Settings.StigViewer.paths.custom.is_valid){
        $stig_path = $PSSTIG.Enviornmental.Settings.StigViewer.paths.custom.use
    }
    if($PSSTIG.Enviornmental.Settings.StigViewer.paths.default.is_valid){
        $stig_path = $PSSTIG.Enviornmental.Settings.StigViewer.paths.default.use
    }

    $separator = $PSSTIG.Dynamic.Settings.Separator
    if(-not(Test-Path "$($psstig_path)$($separator)CHECKLISTS")){
        New-Item -Path "$($psstig_path)$($separator)CHECKLISTS" -ItemType 'Directory'
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "$($psstig_path)$($separator)CHECKLISTS didnt exists in '$($psstig_path)', created it..."
            Write-Host $output_msg -ForegroundColor Yellow
        }
    }else{
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "CHECKLISTS folder exists, good"
            Write-Host $output_msg -ForegroundColor Cyan
        }
    }
    if(-not(Test-Path "$($stig_path)$($separator)CHECKLISTS")){
        New-Item -Path "$($stig_path)$($separator)CHECKLISTS" -ItemType 'Directory'
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "$($psstig_path)$($separator)CHECKLISTS didnt exists in '$($stig_path)', created it..."
            Write-Host $output_msg -ForegroundColor Yellow
        }
    }else{
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "CHECKLISTS folder exists, good"
            Write-Host $output_msg -ForegroundColor Cyan
        }
    }
}

# this will get you stuff from your checklist
Function Get-FromMyCheckList(
    [string]$FromThisCheckList,
    [string]$FromThisSource,
    [string]$Operator,
    [string]$WhereThis,
    [string]$isThis,
    [bool]$MakeViewable
){
   $MyData =  $PSSTIG.SelectFromCheckList(@{
        FromThisCheckList   = $FromThisCheckList
        FromThisSource      = $FromThisSource
        operator            = $Operator
        WhereThis           = $WhereThis
        isThis              = $isThis
    })
    if($MakeViewable){
        $MyData | Format-Table -AutoSize
    }else{
        $MyData
    }
}

# this will generate a report from your checklist
Function New-Report(
    [string]$FromThisCheckList,[string]$FromThisSource
){
    $MyReport = $PSSTIG.GetReport(
        @{
            check_listName  = $FromThisCheckList
            from_source     =  $FromThisSource
        }
    )
    $MyReport
}

# this will update stuff in your checklist
#TODO:: this still needs some work, use the method itself for the time being
#       when using the fuction of this as an interface, it's doesnt recognize the path needed for the update to succeed
#       not sure why that happens
Function Update-MyCheckList(
    [string]$FromThisCheckList,[string]$FromThisSource,[string]$WhereFindingIDIs,[bool]$WithConfirmation,[bool]$WithAutoRefresh,[hashtable]$UpdateTheseThigns
){
   
    $PSSTIG.UpdateMyCheckList(@{
        checklist_name          = $FromThisCheckList
        from_source             = $FromThisSource
        finding_id              = $WhereFindingIDIs
        withComfirmation        = $WithConfirmation
        withAutoRefresh         = $WithAutoRefresh
        userproperties_table    = $UpdateTheseThings
    })
}
Function New-Collection(
    [string]$collection_name,
    [bool]$only_create_local_collection,
    [string]$from_this_xml_data
){

    $PSSTIG.CreateACollection(@{
        collection_name                 = $collection_name
        only_create_local_collection    = $only_create_local_collection
        from_this_xml_data              = $from_this_xml_data
    })

    # we need to tag the collection name
    $collection_name = "$collection_name-STIGS"
    $my_properties = $PSSTIG.GetProperty('*')
    $collection_checklist_path = "$($my_properties.psstig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)$($PSSTIG.Dynamic.Settings.Separator)CHECKLISTS$($PSSTIG.Dynamic.Settings.Separator)"
    $collection_path = "$($my_properties.psstig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)"

    $xml_file_name = $from_this_xml_data.split("$($PSSTIG.Dynamic.Settings.Separator)")[-1]
    $collection_path_xml_file = "$($collection_path)$($PSSTIG.Dynamic.Settings.Separator)$($xml_file_name)"
    [xml]$My_XMLData = Get-Content  $collection_path_xml_file -Raw
    $MyConverted_Data = $PSSTIG.CreateCheckList($fromSender.checklist_title,$My_XMLData)

    # make a checklist template
    $checklist_template_name  = "{0}-cl_template.json" -f $collection_name
    $checklist_Template_file_path = "$collection_path$($PSSTIG.Dynamic.Settings.Separator)$checklist_template_name"
    $MyConverted_Data | ConvertTo-Json -Depth 6 | Out-File -FilePath  $checklist_Template_file_path
    $preconverted_data = Get-Content $checklist_Template_file_path -raw

    # data needs to still be cleaned up
    $replace_1 = $preconverted_data -replace ("\{0\}",'<')
    $replace_2 = $replace_1 -replace ("\{1\}",'>')
    $replace_3 = $replace_2 -replace ("\{2\}",'/')
    $checklist_template_name2 =  "{0}-cl_template.cklb" -f $collection_name
    $checklist_Template2_file_path = "$collection_path$($PSSTIG.Dynamic.Settings.Separator)$checklist_template_name2"
    $replace_3 | Out-File -FilePath $checklist_Template2_file_path
}

Function New-CollectionCheckList([array]$hosts_lists,
[string]$collection_name){
    $function_name = 'New_CollectionCheckList'

    $checklist_name             = $collection_name
    $collection_name            = "$collection_name-STIGS"
    $my_properties              = $PSSTIG.GetProperty('*')
    $collection_checklist_path  = "$($my_properties.psstig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)$($PSSTIG.Dynamic.Settings.Separator)CHECKLISTS$($PSSTIG.Dynamic.Settings.Separator)"
    $collection_folder_path     = "$($my_properties.psstig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)"

    $my_properties = $PSSTIG.GetProperty('*')
    $collection_checklist_path = "$($my_properties.stig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)$($PSSTIG.Dynamic.Settings.Separator)CHECKLISTS$($PSSTIG.Dynamic.Settings.Separator)"
    $collection_path = "$($my_properties.stig_parent_path)$($PSSTIG.Dynamic.Settings.Separator)$($collection_name)"

    $checklist_template_name  = "{0}-cl_template.cklb" -f $collection_name
    $checklist_Template_file_path = "$collection_folder_path$($PSSTIG.Dynamic.Settings.Separator)$checklist_template_name"

    if($PSSTIG.DevSettings.DEBUG_ON){
        $output_msg = "[{0}]:: {1}" -f
        $function_name,
        "getting content from your checklist template '$($checklist_Template_file_path)'"
        Write-Host $output_msg -ForegroundColor Cyan
    }
    $my_template_data = Get-Content -path $checklist_Template_file_path

    foreach($h in $hosts_lists){
        $checklist_tempfile_name  = "$($h)_$($checklist_name)_temp.cklb"
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "temporary checklist file name defined '$($checklist_tempfile_name)'"
            Write-Host $output_msg -ForegroundColor Cyan
        }
       
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "will create this temp file at the following location '$($collection_checklist_path)$($checklist_tempfile_name)'"
            Write-Host $output_msg -ForegroundColor Cyan
        }
        $checklist_file_name  = "$($h)_$($checklist_name).cklb"
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "the actual checklist filename is '$checklist_file_name'"
            Write-Host $output_msg -ForegroundColor Cyan
        }

        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "will create the actual checklist file at the following location '$($collection_checklist_path)$($checklist_file_name)'"
            Write-Host $output_msg -ForegroundColor Cyan
        }
        New-Item -Path $collection_checklist_path -Name "$checklist_tempfile_name" | Out-Null

        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "temp checklist created..."
            Write-Host $output_msg -ForegroundColor Cyan
        }
        Set-Content -Path "$collection_checklist_path$checklist_tempfile_name" -Value $my_template_data
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "temp checklist file popualted with template checklist data..."
            Write-Host $output_msg -ForegroundColor Cyan
        }
        Copy-Item -path "$($collection_checklist_path)$($checklist_tempfile_name)" -Destination "$($collection_checklist_path)$($checklist_file_name)"
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "copied the data temp checklist file to the same location, with new name..."
            Write-Host $output_msg -ForegroundColor Cyan
        }
        Remove-Item "$($collection_checklist_path)$($checklist_tempfile_name)"
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "removed your temp checklist file from your collection..."
            Write-Host $output_msg -ForegroundColor Cyan
        }
        if($PSSTIG.DevSettings.DEBUG_ON){
            $output_msg = "[{0}]:: {1}" -f
            $function_name,
            "checklist '$($checklist_file_name)' is ready`n"
            Write-Host $output_msg -ForegroundColor Green
        }
    }

    if($PSSTIG.DevSettings.DEBUG_ON){
        $output_msg = "[{0}]:: {1}" -f
        $function_name,
        "checklists created for'$($collection_name)' collection, collection is located at '$($collection_checklist_path)'"
        Write-Host $output_msg -ForegroundColor Green
    }
}




# # use this to see the internal references to sources
# Function Show-PSSTIGInternalSources{
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.ViewInternalSourceFolders()
# }

# Function Get-PSSTIGInternalSources([string]$InternalSourceLabel){
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.GetInternalSource($InternalSourceLabel)
# }

# Function Import-PSSTIGFromInternalSource([string]$InternalSourceLabel){
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.ImportSTIGXMLFolder($InternalSourceLabel)
# }
# Function Add-PSSTIGSourceReference([string]$SourceLabel,[string]$SourcePath){
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.AddSourceReference($SourceLabel,$SourcePath)
# }

# Function Show-PSSTIGXMLFile([string]$SourceLabel){
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.GetSTIGXMLFileFromFolder($SourceLabel)
# }

# Function Import-PSSTIGContent([array]$SourceList){
#     #$PSSTIG = Invoke-PSSTIG
#     $PSSTIG.GetSTIGXMLContent($SourceList)
# }

# Function Show-PSSTIGData($FileName,$ViewAs){
#     $PSSTIG.ViewXMLData($FileName,$ViewAs)
# }
# # [void]ExportSTIGsAs([string]$SourceData,[string]$Format,[string]$OutputFolderPath){
# Function Export-PSSTIGAs([psobject]$SourceData,[string]$Format,[string]$OutputFolderPath){
#     $PSSTIG.ExportSTIGsAs($SourceData,$Format,$OutputFolderPath)
# }

# use this to update the check list
# use the updatemychecklsit method, since that thatworks on a larger set
# $PSSTIG.UpdateCheckList(@{
#     checklist_name          = 'SQL_DATABASE'
#     from_source             = '.\PSSTIGDATA'
#     finding_id              = 'V-213927'
#     withComfirmation        = $false
#     withAutoRefresh         = $true
#     userproperties_table    = @{
#         comments = "this is a test"
#     }
# })

# $PSSTIG.CacheMyProperties()
# $PSSTIG.CreateCache("false")
# $PSSTIG.Cache.Settings



# #TODO:: read-through cache needs to work before you dont have to run the set up each time)
# $PSSTIG.Cache.Settings.File

# $PSSTIG.Enviornmental.Settings


# $PSSTIG.DevSettings
# $PSSTIG.Dynamic
# $PSSTIG.Enviornmental.Settings
# # where ever you set the parent, you need the paths as defined by you below f