# refer to the readme.md in this module for more on how to use PSSTIG

# use this to import the module
Import-Module '.\PSSTIG.psm1'

# if needed you can remove the module with the following, but skip it when first running this
Remove-Module -Name "PSSTIG"

# you can check which module are currently defined in your user session
Get-Module -Name "*"

# initialize the module with the following options
$InitializePSSTIGParams = @{

    # WorkingRootDir will need to be where a path to the directory you plan to keep your checklists
    WorkingRootDir          = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library"
    PathTo_StigViewerEXE    = "C:\Users\abraham.hernandez\Documents\Software\STIGViewer_64_3-2-0"
    # defaults_are currently not an option, just leave this false for now..
    UseDefaults             = $false
    # both of these options are below are references to folders in your root as defined by you in WorkingRootDir
    # note: you can use dynamic paths if these locations are in your working path, use full paths if referencing a location
    #       not in your workingrootdir i.e. (\\remotelocation\path\to\location)
    PSSTIGParentPath        = "\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\Phase 1\PSSTIGDATA"
    STIGParentPath          = '.\STIGVIEWERDATA'

}
$PSSTIG = Initialize-PSSTIG @InitializePSSTIGParams

# pass in true to start it if it already isnt running...
$PSSTIG.RestartStigViewer(@{
    program_name                    = "STIG Viewer 3.exe"
    unless_not_currently_running    = $true
})

# created a checklist container
# set only_create_local_collection to false to create both a remote and local collection
# only set to true, when you dont have a local collection but there is a remote location
$PSSTIG.CreateACollection(@{
    collection_name                 = 'SQLInstanceLevel'
    only_create_local_collection    = $false
    from_this_xml_data              = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\STIGVIEWERDATA\U_MS_SQL_Server_2016_Y23M10_STIG\U_MS_SQL_Server_2016_Instance_STIG_V2R10_Manual-xccdf.xml"
})

$NewCollectionParams = @{
        collection_name                 = 'SQLInstanceLevel'
        only_create_local_collection    = $false
        from_this_xml_data              = "C:\Users\abraham.hernandez\Documents\Knowledge_Base\Sources_Library\STIGVIEWERDATA\U_MS_SQL_Server_2016_Y23M10_STIG\U_MS_SQL_Server_2016_Instance_STIG_V2R10_Manual-xccdf.xml"
}
New-Collection @NewCollectionParams


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
$PSSTIG.GetCheckList('Instance_level_stigs','.\PSSTIGDATA')

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

# we need to get our serverlist
$MyHostListData = (Get-Content -path "C:\Users\abraham.hernandez\Documents\LocalRepo\Projects\PSSTIG\PSSTIG\HostsLists.Json") | ConvertFrom-Json

$HostList = $MyHostListData.ServerType.SQLInstance.'1'.name


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




New-CollectionCheckList hosts @('peteresncolsql1') -collection_name 'SQLInstanceLevel'