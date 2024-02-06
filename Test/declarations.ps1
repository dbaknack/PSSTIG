# 1.0 -     set erroractionpreference to stop, and import required modules
$ErrorActionPreference = 'STOP'
Import-Module C:\LocalRepo_2\PSUTILITIES\PSUTILITIES.psd1
Import-Module .\PSSTIG.psd1 -DisableNameChecking

Remove-Module PSSTIG
# 1.1 -   runs the set up when first using tool
$PSSTIG = PSSTIG
$PSSTIG.Initalize(@{
    ParentFolderPath    = '.\Data'
    DataSource          = 'SQLServerInstance'
})


# 2.0 -   define credentials to be used
$myCreds = Get-Credential

# 3.0 -   create sessions to remote hosts
$PSSTIG.CreateSessions(@{
    All         = $true
    HostList    = @()
    Creds       = $myCreds
})

New-PSSession -ComputerName "VIPTO-POSH" -Port 40482 -Credential $myCreds -Name "MST3K"

$myCreds = Get-Credential
$PSSTIG.StoreASession(@{
    SessionName = "MST3K"
    HostName    = "VIPTO-POSH"
    Port        = "40482"
    Creds       = $myCreds
})
# 4.0 -   define levels
$InstanceLevelParams = $PSSTIG.MyHostDataSet(@{
    DataSource  = "SQLServerInstance"
    Level       = "Instance"
})

$TestSession = New-PSSession -ComputerName "VIPTO-POSH" -Port 40482 -Credential $myCreds -Name "MST3K"
# 5.0 -   perform checks
#----------------------------------------------------------------------------------------#
# Finding:V-213988
$findingID = 'V-213988'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams  = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $TestSession
        SourceDataFrom  = $PSSTIG.Configuration.Files.ServerAdminAccountsList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        CheckListType   = $InstanceLevelParam.CheckListType
        DisplayStatus   = $true
    }
    Run-Finding213988  @FunctionParams
}

#----------------------------------------------------------------------------------------#
# Finding:V-213987
$findingID = 'V-213987'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Run-Finding213987 @FunctionParams
}




$PSSTIG.UpdateComment(@{
    CheckListName   = "PETERESNCOLSQL1__SQLServerInstance"
    FindingID       = "V-213988"
    Comment         = "this is a test"
})

$PSSTIG.UpdateStatus(@{
    CheckListName   = "PETERESNCOLSQL1__SQLServerInstance"
    FindingID       = "V-214042"
    Status         = "open"
})

$PSSTIG.GetAllCheckListFindings(@{
    CheckListName = 'PETERESNCOLSQL1__SQLServerInstance'
})



# use this to restart stig viewer
Run-Program -program_alias 'sv3' -action 'open'



# use this to get your checklist data
$PSSTIG.GetCheckListData(@{
    CheckListName = "PETERESNCOLSQL1__SQLServerInstance"
})


$PSSTIG.UpdateCheckListTitle(@{
    CheckListName = "PETERESNCOLSQL1__SQLServerInstance"
    Title = "PETERESNCOLSQL1_CheckList"
})


# on a needed basis, remove a check list
$PSSTIG.DeleteChecklist(@{
    CheckListName = "PETERESNCOLSQL1__SQLServerInstance"
})





# this will pull in the entire stig data
$myStigData = $PSSTIG.GetCheckListData(@{ CheckListName = "hostName_instance_checklist" })
$myStigData.title = 
$myrules =$myStigData.stigs.rules
foreach($rule in $myrules){
 $rule.group_id  
}

