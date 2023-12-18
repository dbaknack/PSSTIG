#[-------------------------------------------------------- COMMANDS ---------------------------------------------------]   [ --------------------------------- NOTES --------------------------- ]
# ----------------------------------------------------------------------------------------------------------------------
# step 1) Module Import:
Import-Module '.\PSSTIG.psm1'

# ----------------------------------------------------------------------------------------------------------------------
# ADHOC step(s))
#-Note:: Steps labeled as 'ADHOC' are only ran as needed, check out the comment next to the command to see what it does
Remove-Module -Name "PSSTIG"                                                                                          # this will remove the module from your current powershell session.
Get-Module -Name "*"                                                                                                        # if you need to validate the module is loaded or not, you can run this.

# step 2.2) STIGParentPath points to a folder called 'STIGVIEWERDATA', if you dont already have a folder of that name,
#           create if first.
$InitializePSSTIGParams = @{
    WorkingRootDir          = "./"                                                                                          # this can be anything, but its needed.
    PathTo_StigViewerEXE    = "\\Mac\Home\Documents\Knowledge_Base\Software\STIGViewer_64_3-2-0"                           # so you can restart the stigviewer, you need the parent of the .exe.
    UseDefaults             = $false                                                                                         # this will always be false, no other consideration needed.
    PSSTIGParentPath        = "Z:\LocalRepo\PSSTIG\PSSTIGDATA"                                                                                # this can be a local/remote file location.
    STIGParentPath          = "Z:\LocalRepo\PSSTIG\STIGVIEWERDATA"                                                                            # this can be a local/remote file location.
}
$PSSTIG = Initialize-PSSTIG @InitializePSSTIGParams

$PSSTIG.insertInto(@{
    this_file = 'host_list'
    this_data = @{
        # dont use '-' in your checklist name
        checklist_name          = 'DEVSQL01'
        from_source             = 'stig_parent_path'
        from_collection         = 'SQLInstanceLevel'
        access_name             = 'DEV-SQL01'
        is_sql_server           = 1
        using_sql_login         = 0
        sql_instance_name       = 'DEV-SQL01\SANDBOX'
        enclave                 = ''
        domain                  = 'DEVLAB.com'
        need_creds              = 1
        cred_type_to_use        = 'DEVLAB'
        host_type               = 'SQLInstance'
        use_general_properties  = 1
        where                   = ''
        operator                = ''
        is_this                 = ''
    }
}) 

$PSSTIG.stashCred(@{
    from_PIV        = $false
    cred_name       = 'DEVLAB'
    cred_is         = 'WindowsAuth'
    for_domain      = 'DEVLAB.com'
    for_this_host   = 'DEV-SQL01'
    user_name       = 'devlab\administrator'
    pw              = 'P@55word'
})

$PSSTIG.getStashedCred(@{
    cred_name       = 'DEVLAB'
    cred_is         = 'WindowsAuth'
    for_domain      = 'DEVLAB.com'
    for_this_host   = 'DEV-SQL01'
})

# ----------------------------------------------------------------------------------------------------------------------
# step 3) Creating a Collection:
#-NOTE:: 'collection_name' is what the folder, that will contain your checklist files, will be named.
#        'only_create_local_collection', just leave as false,
#        'from_this_xml_data'; you can get the xml that the stigviewer uses, from the DCSA site. the file will be in a
#        zip folder, pull the .xml file out and keep it somehwere locally, you just need the full path to it
#        to run this command successfull.

#-Note:: you don't need to run this command again once you have created the collection. you only need to run it if you
#        are creating a new collection. also nothing will happen if you run it again by accident or something. wont
#        overwrite existing collections.
$NewCollectionParams = @{
        collection_name                 = 'SQLInstanceLevel'                                                               # collection need a name, use something descriptive
        only_create_local_collection    = $false                                                                            # if false, it will create the needed folders in both your 'PSSTIGParentPath'
        from_this_xml_data              = ".\Documentation\U_MS_SQL_Server_2016_Instance_STIG_V2R10_Manual-xccdf.xml"       # and 'STIGParentPath'
}                                                                                                                           # if true, it will only create the needed folder in the 'PSSTIGParentPath' path
New-Collection @NewCollectionParams

# ----------------------------------------------------------------------------------------------------------------------
# step 4)  Creating Checklists For Each Host:
#-Note::    if your hostname has '\', replace it with '-', this is a NFTS thing, file names cannot have '\' in them. that
#           being said, you can still refer to those checklists by hostname where the name contains '\', the mapping is
#           done internally.
$my_host_list = $PSSTIG.getDataFrom('host_list')
foreach($my_host in $my_host_list){
    New-CollectionCheckList -hosts $my_host.checklist_name -collection_name $my_host.from_collection
}


# ----------------------------------------------------------------------------------------------------------------------
# step 5)   Get Checklist Data From Collection:
#-Note::    if you provide 'none' as an operator value, whatever you specified in ther 'where', and 'isthis' fields, will
#           be ignored. eq means 'equal'
#           only the eq, and none, operations work for some reason. just fyi... will fix later
$PSSTIG.SelectFromCheckThisList(@{
    ForHostName         = 'DEVSQL01'                                                                                            # each host you created will have a checklist created for it
    FromThisSource      = 'stig_parent_path'                                                                                # the collection is stored in 1 of 2 places, provide 1 of the places
    FromThisCollection  = 'SQLInstanceLevel'                                                                                # in the place the collection is, the collection will have a name, provide it
    Where               = 'severity'                                                                                        # each checklist has several properties to filter on, provide one of those properties
    Operator            = 'none'                                                                                            # your propertie will be filtered on a given operator, provide that operator
    isThis              = 'medium'                                                                                          # the checklist property, will run the operation defined by your operator where the property value is this
})| Select-Object -Property ('status','UpdateAt','group_id','Severity') | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# step 6)   Update Checklist Data From Collection:
#           updating a check list means you need to get the the data
#           every script is linked to a finding, you need to have something to do that
#           each host will end up with a session and it's checklist
$my_hosts                   = $PSSTIG.getDataFrom('host_list')
$my_sessions_table          = @{}
foreach($my_host in $my_hosts){
    # the session name is defined by the access_name 
    $session_name = "{0}" -f "$($my_host.access_name)"


    if($my_host.using_sql_login -eq 0){
        $cred_is = 'WindowsAuth'
    }else{
        $cred_is = 'SQLLogin'
    }

    # credentials are searched for for the credential
    $my_creds = $PSSTIG.getStashedCred(@{
        cred_name       = $my_host.cred_type_to_use
        cred_is         = $cred_is
        for_domain      = $my_host.domain
        for_this_host   = $my_host.access_name
    })

    # the credentials are used to create the session for the host
    $for_session = New-Object -TypeName PSCredential -ArgumentList  $my_creds.user_name,$my_creds.pw
    $my_session = (New-PSSession -Name $session_name -ComputerName "$($my_host.access_name)" -Credential $for_session  -ErrorAction SilentlyContinue)
    # the session it self if used to define the session properties to then add then to host itself
    $my_sessions_table.Add($my_session.name,@{})
    $my_sessions_table.($my_session.name) = @{
        the_session = $my_session
        state       = $my_session.State
        id          = $my_session.id
        my_host     = $my_host
    }
}

# script library gets defined
$scripts_list               = $PSSTIG.GetScriptProperties()

# the general properties define the critiera by which checklist data is search by
$GeneralUpdateProperties    = @{                                                                                               # general update properties are properties that will apply to all your hosts
    where       = 'status'
    operator    = 'eq'
    is_this     = 'not_reviewed'
}

# at this stage there should be a session for each of the host in the host list that was able to create one
foreach($session in $my_sessions_table.keys){

    # each host object defines what  kind of properties to use
    # if the object value is '1' then it will use the defined GeneralUpdateProperties defined by you
    # it might be better to think of general update properties as a categorical search filter, there can be many, but this one is do an audit
    if($my_sessions_table.$session.my_host.use_general_properties -eq 1){
        $my_sessions_table.$session.my_host.where      = $GeneralUpdateProperties.where
        $my_sessions_table.$session.my_host.operator   = $GeneralUpdateProperties.operator
        $my_sessions_table.$session.my_host.is_this    = $GeneralUpdateProperties.is_this
    }
    
    # data is the returned from the select list where the search criteria is met
    $my_data =  $PSSTIG.SelectFromCheckThisList(@{
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

# each session is iterated on again, 
foreach($sesion in $my_sessions_table.keys){

    # a counter for each session is seeded
    $total_jobs_needed = 0

    # the seassion then looks in its checklists, for the finding id 
    foreach($finding in $my_sessions_table.$session.checklist_data){
        if($finding.group_id -match '(V-)(.*)'){
            $finding_id = $Matches[2]
        }

        # now conditionally see if the finding matches a given criteria
        $finding_is_not_reviewed = [bool]
        if($my_sessions_table.$session.my_host.operator -eq 'eq'){
            $finding_is_not_reviewed = $true
            $working_finding_data = $finding | Select-Object -Property * | Where-Object {$_.($my_sessions_table.$session.my_host.where) -eq ($my_sessions_table.$session.my_host.is_this)}
        }else{
            $finding_is_not_reviewed = $false
        }

        # it the criteria is met, get the script that is approriate to run, given what it means to match that criteria
        if($finding_is_not_reviewed){
            
            #this is done by doing using the finding id and the script id wich will be the same
            foreach($script in $my_sessions_table.$session.script_table.keys){
                $script_finding_id  =  $my_sessions_table.$session.script_table.$script.finding_id
                if($script_finding_id -match $finding_id){
                    $script_path = $my_sessions_table.$session.script_table.$script.script_path

                    # matching the criteria means a script will be ran, that will happen in it's own job
                    # the counter will track how many jobs
                    $total_jobs_needed = $total_jobs_needed + 1
                }
            }
        }
    }

    # now for each of those scripts that need to be ran in their rescpective session,
    # they need to be contraints to a batch to ran till the total jobs requried, finish
    for ($i = 1; $i -le $total_jobs_needed; $i += $batchSize){
        $batchStart = $i
        $batchEnd = [math]::Min($i + $batchSize - 1, $totalJobs)
    
        # Create and start jobs for the current batch
        $jobs = Invoke-Command -Session $my_sessions_table.$session.the_session -FilePath $script_path -AsJob

        # Wait for the current batch of jobs to complete
        $null = Wait-Job -Job $jobs

        foreach($job in $jobs){
            $my_results = $job | Receive-Job
        }
        $working_finding_data.status = 'not_applicable'
        $finding = $working_finding_data
        for ($i = 0; $i -le ($my_sessions_table.$session.checklist_data).Length; $i++) {
            if(($my_sessions_table.$session.checklist_data)[$i].group_id -eq $finding.group_id){
                $my_sessions_table.$session.checklist_data[$i].status = 'not_applicable'
                $PSSTIG.UpdateMyCheckList(@{
                    checklist_name          = $my_sessions_table.$session.my_host.checklist_name
                    from_source             = $my_sessions_table.$session.my_host.from_source
                    finding_id              = $finding_id
                    withComfirmation        = $false
                    withAutoRefresh         = $true
                    userproperties_table    = @{
                        status = "not_a_finding"
                    }
                })
            }
        }
    }

}

get-job -Name "*" | Remove-Job


# Total number of jobs
$totalJobs = 542

# Batch size
$batchSize = 10

# Counter for job names
$jobCounter = 1

# Loop through jobs in batches
for ($i = 1; $i -le $totalJobs; $i += $batchSize) {
    $batchStart = $i
    $batchEnd = [math]::Min($i + $batchSize - 1, $totalJobs)

    # Create and start jobs for the current batch
    $jobs = $batchStart..$batchEnd | ForEach-Object {
        $jobScriptBlock = {
            # Your job script goes here
            # This is just a placeholder
            Start-Sleep -Seconds 5
            Write-Host "Job $using:jobCounter completed."
        }

        $jobName = "Job$jobCounter"
        Start-Job -ScriptBlock $jobScriptBlock -Name $jobName
        $jobCounter++
    }

    # Wait for the current batch of jobs to complete
    $null = Wait-Job -Job $jobs

    # Receive and remove the completed jobs
    $null = Receive-Job -Job $jobs | ForEach-Object { Write-Host $_ }
    $null = Remove-Job -Job $jobs
}
# ----------------------------------------------------------------------------------------------------------------------
#       ADHOC step(s)
#-Note: depending on your powershell execution policy, you might be able to pull the stigs you need from within your session.
#       otherwize, download it manually.
$url            = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_SQL_Server_2016_Y23M10_STIG.zip"
$outputPath     = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\test_local_download_folder"
$zipFilePath    = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\test_local_download_folder\U_MS_SQL_Server_2016_Y23M10_STIG.zip"
$extractPath    = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\test_local_download_folder\"

Invoke-WebRequest -Uri $url -OutFile $outputPath
Expand-Archive -Path $zipFilePath -DestinationPath $extractPath
Invoke-WebRequest -Uri $url -OutFile $outputPath


# ----------------------------------------------------------------------------------------------------------------------
# ADHOC step(s)
$PSSTIG.RestartStigViewer(@{                                                                                              
    program_name                    = "STIG Viewer 3.exe"                                                                  # this will restart the stigviewer.
    unless_not_currently_running    = $true                                                                                 # if false, it wont do anything if you dont have stigviewer running.
})    








# here are the different ways you can remove a collection
$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'local_and_remote'
    withComfirmation    = $false
})
$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'remote'
    withComfirmation    = $false
})
$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'local'
    withComfirmation    = $false
})

$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'local_and_remote'
    withComfirmation    = $true
})
$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'remote'
    withComfirmation    = $true
})
$PSSTIG.RemoveACollection(@{
    collection_name     = 'SQLInstanceLevel'
    collection_type     = 'local'
    withComfirmation    = $true
})
# you can view a filtered list of your stowed properties with this command here
$PSSTIG.GetProperty('*')

# instructions::    you need to have a check lists to work from first,
#                   refer to .\Documentation\README.md documentation in this module on how to generate the check list prior to continuing

# you can get the data from the check lists with this command, the parent of the CHECKLISTS folder is used as the source, so you only need to specify that
# along with the name of the check list at that source location
# this gets a high order dataset of checklists data, if you want just the checklist data, use Get-FromMyCheckList instead
# instructions::      checklist_name, checklists source
$PSSTIG.GetCheckList('SQLInstanceLevel','PSSTIGDATA')

# the stigviewer now knows where the check list is, but PSSTIG does not, you can run the following command to sync the data from stig viewer over to PSSTIG
$PSSTIG.SyncCheckListChanged('Instance_level_stigs','.\STIGVIEWERDATA')


# at this point things are at up to talk to each other
# to select data from your checklists, use the following command
$MySelectFromCheckListParams = @{
    FromThisCheckList   = 'Instance_level_stigs'
    FromThisSource      = '.\PSSTIGDATA'
    operator            = 'eq'
    WhereThis           = 'severity'
    isThis              = 'high'

    # use this when you want to have the results look a bit more ordered in the output
    # when part of an automated process, this can be false
    MakeViewable        = $true
}
$MyData = Get-FromMyCheckList @MySelectFromCheckListParams
$MyData

# use this to generate a report from a given checklist and source
New-Report -FromThisCheckList 'Checklist_SQL_Database_2014' -FromThisSource '.\PSSTIGDATA'


# youll need to restart the sw tool after a change in order for you to view it
# note that you need to set the path to the exe so you can do this, otherwise you will need to do this manually
$PSSTIG.RestartStigViewer()

# use this to initalize the comment section
$PSSTIG.ApplyCommentsTemplateToFinding(@{
    template_name           = 'Comments_T01.md'
    checklist_name          = 'SQL_DATABASE'
    from_source             = '.\STIGVIEWERDATA'
    finding_id              = '*'
    withComfirmation        = $false
    withAutoRefresh         = $true
})
$PSSTIG.RestartStigViewer()

# use this when you want to update something in your checklist
$PSSTIG.UpdateMyCheckList(@{
    checklist_name          = 'SQL_DATABASE'
    from_source             = '.\PSSTIGDATA'
    finding_id              = '*'
    withComfirmation        = $false
    withAutoRefresh         = $true
    userproperties_table    = @{
        status = "not_a_finding"
    }
})











$my_sessions_table | ForEach-Object {
    Invoke-Command -Session $_ -ScriptBlock $UDFunctions.'Invoke-UDFSQLCommand'.ScriptBlock.Command -ArgumentList @InvokeUDFSQLCommand3Params -AsJob
}







$results = Invoke-Command -Session  (get-pssession -id 1) -FilePath "C:\Users\abraham.hernandez\Documents\LocalRepo\Projects\PSSTIG\PSSTIG\ScriptLibrary\214042_check_sqlbrowser_is_running.ps1"
$results.check_results


$PSSTIG.getStashedCred(@{
    cred_name       = 'DEVLAB'
    cred_is         = 'WindowsAuth'
    for_domain      = 'DEVLAB.com'
    for_this_host   = 'DEV-SQL01'
})


$UDFunctions = [ordered]@{}
$UDFunctions.'Invoke-UDFSQLCommand' +=@{
    BlockName   = 'Invoke-UDFSQLCommand'
    Description = "Makes a connection to the sql instance running on the host"
    ExecCmd     = {&($UDFunctions.'Invoke-UDFSQLCommand').Scriptblock.command`
        -use_sql_login $use_sql_login`
        -sql_login_name $sql_login_name`
        -sql_login_password $sql_login_password`
        -instance_name $instance_name`
        -tsql_command $tsql_command`
        -process_name $process_name}
    ScriptBlock = @{
        Command = {
            param(
                [bool]$use_sql_login,
                [string]$sql_login_name,
                [securestring]$sql_login_password,
                [string]$instance_name,
                [string]$database_name,
                [string]$tsql_command,
                [string]$process_name
            )
       
        # depending if you're going to use sql login or not, the connection string will be built differently
        if($use_sql_login -eq $true){
            $connection_template    = "
                server                  = {0};
                database                = {1};
                trusted_connection      = {2};
                user id                 = {3};
                integrated security     = {4};
                password                = {5};
                application name        = {6};"
            $connection_template = $connection_template -f
                $instance_name,
                $database_name,
                'false',
                $sql_login_name,
                'true',
                $sql_login_password,
                $process_name;
        }
       
        # this will run when using windows authentication
        if($use_sql_login -eq $false){
            $connection_template    = "
                server              = {0};
                database            = {1};
                trusted_connection  = {2};
                application name    = {3};"
       
            $connection_template = $connection_template -f
                $instance_name,
                $database_name,
                'true',
                $process_name;
        }
       
        # here we use the connection string to open the sql connection
        $sqlconnection = new-object system.data.sqlclient.sqlconnection
        $sqlconnection.connectionstring = $connection_template
        $sqlconnection.open()
       
        $sqlcommand = new-object system.data.sqlclient.sqlcommand
        $sqlcommand.connection = $sqlconnection
        $sqlcommand.commandtext = $tsql_command
        $sqladapter = new-object system.data.sqlclient.sqldataadapter
        $sqladapter.selectcommand = $sqlcommand
       
        $dataset = new-object system.data.dataset
        $sqladapter.fill($dataset) | out-null
       
        # close the connection when things are done
        $results_collection = @{[string]$($instance_name) = $dataset.tables}
        if($sqlconnection.state -match 'open'){
            $sqlconnection.close()
            $sqlconnection.dispose()
        }
       
        # this holds our results to return
        $results_collection
        }
    }
}

$InvokeUDFSQLCommand3Params = @{
    instance_name      = 'DEV-SQL01\SANDBOX01'
    database_name      = 'master'
    process_name       = 'test'
    use_sql_login      = $false
    tsql_command       = 'select * from sys.databases'
    sql_login_password = ConvertTo-SecureString -String 'na' -AsPlainText -Force
    sql_login_name     = 'na'
}


$issessions | ForEach-Object {
    Invoke-Command -Session $_ -ScriptBlock $UDFunctions.'Invoke-UDFSQLCommand'.ScriptBlock.Command -ArgumentList @InvokeUDFSQLCommand3Params -AsJob
}

$instance_name      = 'DEV-SQL01\SANDBOX01'
$database_name      = 'master'
$process_name       = 'test'
$use_sql_login      = $false
$tsql_command       = 'select * from sys.databases'
$sql_login_password = ConvertTo-SecureString -String 'na' -AsPlainText -Force
$sql_login_name     = 'na'



$host_name_list         =  @("")
$use_a_sql_connection   = $true
# here we open up all the session we need for all the host we are connecting to
foreach($host_name in $host_name_list){
    New-PSSession -ComputerName $host_name -name ("sessionfor_{0}" -f $host_name) -Credential $creds | Out-Null
}
$My_Sessions  = Get-PSSession -Name "sessionfor_*"
$My_Sessions  |ForEach-Object {
    Invoke-Command -ComputerName "" -Credential $creds -ScriptBlock $UDFunctions.'Invoke-UDFSQLCommand'.ScriptBlock.Command `
    -ArgumentList $use_sql_login,$sql_login_name,$sql_login_password,$instance_name,$database_name,$tsql_command,$process_name -AsJob
}



# Alternatively, you can create a PSCredential object directly with a secure string
$username = "devlab\administrator"
$securePassword = ConvertTo-SecureString -String "P@55word" -AsPlainText -Force
$credentials = New-Object -TypeName PSCredential -ArgumentList $username, $securePassword
Get-Credential  | Get-Member
Invoke-Command  DEV-SQL01 -ScriptBlock {(Get-WmiObject Win32_ComputerSystem).Domain} -Credential $credentials

