#[-------------------------------------------------------- COMMANDS ---------------------------------------------------]   [ --------------------------------- NOTES --------------------------- ]
# ----------------------------------------------------------------------------------------------------------------------
# step 1) Module Import:
Import-Module '.\PSSTIG.psm1'

# ----------------------------------------------------------------------------------------------------------------------
# ADHOC step(s))
#-Note:: Steps labeled as 'ADHOC' are only ran as needed, check out the comment next to the command to see what it does
Remove-Module -Name "PSSTIG"                                                                                                # this will remove the module from your current powershell session.
Get-Module -Name "*"                                                                                                        # if you need to validate the module is loaded or not, you can run this.

# ----------------------------------------------------------------------------------------------------------------------
# step 2) Initialize PSSTIG:
#-NOTE:: Prior to continuing these steps, do the following 2 things....
# step 2.1) PSSTIGParentPath points a folder called 'PSSTIGDATA', if you dont already have a folder of that name there,
#           create it first.

# step 2.2) STIGParentPath points to a folder called 'STIGVIEWERDATA', if you dont already have a folder of that name,
#           create if first.
$InitializePSSTIGParams = @{
    WorkingRootDir          = "./"                                                                                          # this can be anything, but its needed.
    PathTo_StigViewerEXE    = "C:\Users\abraham.hernandez\Documents\Software\STIGViewer_64_3-2-0"                           # so you can restart the stigviewer, you need the parent of the .exe.
    UseDefaults             = $false                                                                                         # this will always be false, no other consideration needed.
    PSSTIGParentPath        = "./PSSTIGDATA"                                                                                # this can be a local/remote file location.
    STIGParentPath          = "./STIGVIEWERDATA"                                                                            # this can be a local/remote file location.
}
$PSSTIG = Initialize-PSSTIG @InitializePSSTIGParams 
$my_data = $PSSTIG.getDataFrom('host_list') 
$fromSender  = $PSSTIG.insertInto(@{
    this_file = 'host_list'
    this_data = @{
        checklist_name          = 'peteresncolsql1'
        from_source             = 'stig_parent_path'
        from_collection         = 'SQLInstanceLevel'
        access_name             = 'peteresncolsql1'
        enclave                 = 'NIPERNET'
        cred_type_to_use        = 'RES'
        host_type               = 'server'
        use_general_properties  = 1
        where                   = $null
        operator                = $null
        is_this                 = $null
    }
})
$fromSender.this_data
$columns_that_are_null_list = @()
foreach($entry_key in $my_data.this_data.keys){
    if($null -eq ($my_data.this_data).$entry_key){
        $columns_that_are_null_list += $entry_key
    }
}
$missing_columns

$PSSTIG.paths_table.'host_list'.table.null_exception_list



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
})                                                                                                                         # if true, even if the stigviewer is not running, it will start it up.

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
        from_this_xml_data              = "./Documentation/U_MS_SQL_Server_2016_Instance_STIG_V2R10_Manual-xccdf.xml"       # and 'STIGParentPath'
}                                                                                                                           # if true, it will only create the needed folder in the 'PSSTIGParentPath' path
New-Collection @NewCollectionParams

# ----------------------------------------------------------------------------------------------------------------------
# step 4)  Creating Checklists For Each Host:
#-Note::    if your hostname has '\', replace it with '-', this is a NFTS thing, file names cannot have '\' in them. that
#           being said, you can still refer to those checklists by hostname where the name contains '\', the mapping is
#           done internally.
$collection_name = 'SQLInstanceLevel'
$hosts_lists = @(
'test'
)
New-CollectionCheckList -hosts $hosts_lists -collection_name $collection_name

# ----------------------------------------------------------------------------------------------------------------------
# step 5)   Get Checklist Data From Collection:
#-Note::    if you provide 'none' as an operator value, whatever you specified in ther 'where', and 'isthis' fields, will
#           be ignored. eq means 'equal'
#           only the eq, and none, operations work for some reason. just fyi... will fix later
$MyData = $PSSTIG.SelectFromCheckThisList(@{
    ForHostName         = 'test'                                                                                            # each host you created will have a checklist created for it
    FromThisSource      = 'stig_parent_path'                                                                                # the collection is stored in 1 of 2 places, provide 1 of the places
    FromThisCollection  = 'SQLInstanceLevel'                                                                                # in the place the collection is, the collection will have a name, provide it
    Where               = 'severity'                                                                                        # each checklist has several properties to filter on, provide one of those properties
    Operator            = 'none'                                                                                            # your propertie will be filtered on a given operator, provide that operator
    isThis              = 'medium'                                                                                          # the checklist property, will run the operation defined by your operator where the property value is this
})
$MyData | Select-Object -Property ('status','UpdateAt','group_id','Severity') | Format-Table -AutoSize

# ----------------------------------------------------------------------------------------------------------------------
# step 6)   Update Checklist Data From Collection:
#           updating a check list means you need to get the the data
#           every script is linked to a finding, you need to have something to do that

# declare vars
$show_message_params = @{
    method_name  = "SQLInstanceLevel"
    message      = ""
    message_type = ""
}

# the host list is used to define the conditions used when mapping a host and its checklist
# to the script file used to do either a check
$my_host_lists              = (Get-Content -path "$(Get-ScriptPath)\HostsLists\host_list.csv") | ConvertFrom-Csv                                # get your serverlist from a defined csv file that contains the hosts you want to loop on
$my_host_lists | ft -AutoSize
$my_scripts                 = $PSSTIG.GetProperty('*')
$my_creds                   = Get-SmartCardCred
# general properties are those properties defined by you prior to executing a
$GeneralUpdateProperties    = @{                                                                                               # general update properties are properties that will apply to all your hosts
    where       = 'status'
    operator    = 'eq'
    is_this     = 'not_reviewed'
}

# here we want to populate our hostlist table by iterating on our host list, make sure to use the access_name


$HostTableList = @()
foreach($my_host in $my_host_lists){

    # each host object defines what  kind of properties to use
    # if the object value is '1' then it will use the defined GeneralUpdateProperties defined by you
    if($my_host.use_general_properties -eq 1){
        $my_host.where      = $GeneralUpdateProperties.where
        $my_host.operator   = $GeneralUpdateProperties.operator
        $my_host.is_this    = $GeneralUpdateProperties.is_this
    }
   
}

  # each host will need its own session
foreach($host_properties in $HostTableList){
 
    $session_created = [bool]
    try{
        $session_created = $true
        New-PSSession -ComputerName $host_properties.host_name -name ("sessionfor_{0}" -f ($host_properties.host_name)) -Credential $my_creds  -ErrorAction stop | Out-Null
        $show_message_params.message_type   = 'success'
        $show_message_params.message        = "session succesfully created to host '$($host_properties.host_name)'"
    }catch{
        $session_created = $false
        $show_message_params.message_type   = 'failed'
        $show_message_params.message        = "session unable to be created to host '$($host_properties.host_name)'"
    }
    #display feedback
    Show-Message @show_message_params
}


    $my_data =  $PSSTIG.SelectFromCheckThisList(@{
        ForHostName         = $host_properties.host_name                                                            
        FromThisSource      = $host_properties.from_source                                                                    
        FromThisCollection  = $host_properties.from_collection                                                                          
        Where               = $host_update_properties.where                                                                                  
        Operator            = $host_update_properties.operator                                                                                        
        isThis              = $host_update_properties.is_this                                                                                
    })

    foreach($finding_properties in $my_data){
       
        $finding_id = ($finding_properties.group_id).Substring(2)
       
        foreach($properties in $my_scripts.keys){
            if($finding_id -eq ($my_scripts.$properties.finding_id)){
                $my_scripts.$properties.script_level
            }
        }
    }










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
$PSSTIG.GetCheckList('SQLInstanceLevel','\\MST3K\LocalShare\PSSTIGDATA')

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

$Res_Creds = Get-SmartCardCred






$hostNAme.count


foreach($remote_host in $HostList){
    # each host needs a session to do work in
    # each session name should follow a convention
    # sessiontype_for_hostname
    $session_name = "[{0}]_{1}" -f
    "CHECK_SESSION",
    "$remote_host"

    # in order to build a connection, you need your credentials and the servername
    New-PSSession -Name $session_name -ComputerName $remote_host -Credential $Res_Creds
}



Invoke-Command -Session  (get-pssession -id 4) -ScriptBlock{
    Get-Service -Name "SQLBrowser" 
} 


$results = Invoke-Command -Session  (get-pssession -id 1) -FilePath "C:\Users\abraham.hernandez\Documents\LocalRepo\Projects\PSSTIG\PSSTIG\ScriptLibrary\214042_check_sqlbrowser_is_running.ps1"
$results.check_results





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


$test = Get-Job | Receive-Job