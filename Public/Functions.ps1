Function PSSTIG {
    $PSSTIG =  [PSSTIG]::new()
    $PSSTIG
}
Function Invoke-UDFSQLCommand{
    param(
        [hashtable]$Query_Params
    )

    $processname = 'Invoke-UDFSQLCommand'
    $sqlconnectionstring = "
        server                          = $($Query_Params.InstanceName);
        database                        = $($Query_Params.DatabaseName);
        trusted_connection              = true;
        application name                = $processname;"
    # sql connection, setup call
    $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
    $sqlconnection.connectionstring = $sqlconnectionstring
    $sqlconnection.open()
    $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
    $sqlcommand.connection          = $sqlconnection
    $sqlcommand.commandtext         = ($Query_Params.Query)
    # sql connection, handle returned results
    $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
    $sqladapter.selectcommand       = $sqlcommand
    $dataset                        = new-object system.data.dataset
    $sqladapter.fill($dataset) | out-null
    $resultsreturned                = $null
    $resultsreturned               += $dataset.tables
    $sqlconnection.close()      # the session opens, but it will not close as expected
    $sqlconnection.dispose()    # TO-DO: make sure the connection does close
    $resultsreturned
}
Function Invoke-Finding213988{
    param(
        [string]$Hostname,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [string]$CheckListType,
        [switch]$DisplayStatus
    )
   
    # this host has issues with the cmdlet, not sure why
    if($Hostname -eq "PETERESNSWSQL01"){
        $results = net localgroup administrators
        $results = $results -split "`n" | Select-Object -Skip 6
        $newResults = @()
        foreach($result in $results){
            if(($result -ne 'The command completed successfully.')){
               $newResults += $result
            }
        }
        $finalResults = @()
        foreach($result in $newResults){
            if(($result -ne '')){
               $finalResults += $result
            }
        }
        $groupResults = @()
        foreach($finalResult in $finalResults){
            $groupResults += [pscustomobject]@{Name = $finalResult ; PrincipalSource = 'ActiveDirectory'}
        }
    }else{
        $groupResults  = Invoke-Command -Session $Session -ScriptBlock {Get-LocalGroupMember -Group "Administrators"}
    }
    if(-not(Test-Path -Path $SourceDataFrom)){
        New-Item -ItemType File -Path $SourceDataFrom | Out-Null
    }
    $myContent      = Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ","
    $headingString  = [string]
    $myHostName     = Invoke-Command -Session $Session -ScriptBlock {hostname}
    $headingsList   = @("RecordID","HostName","Name","PrincipalSource","Description")
    $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')


    if(0 -eq [int]$myContent.count){
        Add-Content -Path $SourceDataFrom -Value $headingString
    }

    if(0 -eq [int]$myContent.count){
        [int]$recordID = 1
    }else{
        [int]$recordID = [int]$myContent.RecordID[-1]+1
    }
   
    $myEntriesList  = @()
    foreach($accountName in $groupResults){
        $entryString    = [string]
        $myEntry        = @("$recordID","$myHostName","$($accountName.Name)","$($accountName.PrincipalSource)","NULL")
        $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
        $myEntriesList += $entryString
        $recordID       = ($recordID) + 1
    }
   
    $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
    $myCurrenEntriesTable   = $myContent | Group-Object -Property 'HostName' -AsHashTable

    $findingStatus          = "not_a_finding"
    $nullDescriptionList    = @()
    $noEntryExistsList      = @()
    $noAccountNameExistList = @()
    foreach($newEntry in $newEntriesList){
        $newEntryHostName = $newEntry.HostName
        $currentEntriesObject = $myCurrenEntriesTable.$newEntryHostName
       
       
        # are there entries for this hostname?
        $HostNameEntryExists = [bool]
        if($currentEntriesObject.HostName.count -eq 0){
            $HostNameEntryExists = $false
        }else{
            $HostNameEntryExists = $true
        }

        # if the entry doesnt already exist, then it gets added
        if(-not($HostNameEntryExists)){
            $myEntry = ('"{0}","{1}","{2}","{3}","{4}"' -f
                $newEntry.RecordID,
                $newEntry.HostName,
                $newEntry.Name,
                $newEntry.PrincipalSource,
                $newEntry.Description)
            Add-Content -Path $SourceDataFrom -Value $myEntry
            $findingStatus      = "open"
            $noEntryExistsList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
        # is the name of the account in the list?
        $accountNameExists = [bool]
        if(-not($currentEntriesObject.Name -contains $newEntry.Name)){
            $accountNameExists = $false
        }else{
            $accountNameExists = $true
        }

        if( $accountNameExists -eq $false){
            $findingStatus          = "open"
            $noAccountNameExistList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }

        $currentEntryCheck = $currentEntriesObject |
            Select-Object -Property @('Name','Description') |
            Where-Object {$_.Name -eq ($newEntry.name)}

        $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
       
        if($entryDescriptionIsNUll){
            $findingStatus          = "open"
            $nullDescriptionList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
    }

    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $myCommentList = @()
    if($findingStatus -eq "open"){
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
        $myCommentList += ' '
        foreach($nullValue in $nullDescriptionList){
            $myCommentList +=  "   Host - '$($nullValue.HostName)', admin account '$($nullValue.Name)' is not documentend."
        }
    }else{
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
    }
   
   
    $PSSTIG.UpdateComment(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Comment         = ($myCommentList -join "`n")
    })
   
    $PSSTIG.UpdateStatus(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Status          = $findingStatus
    })

    if($DisplayStatus){
        $PSSTIG.GetFindingInfo(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
    }
}
Function Invoke-Finding213987{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )

    $myScripts = $PSSTIG.GetSQLQuery(@{
        FindingID = $FindingID
    })
    # this script is not working in terms of its definiton as a query param, string is used instead for now
    #$principalsScript   = $myScripts['script_01']
   

    $instanceNameList   = $InstanceLevelParam.CheckListName -split '_'
    $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

    # run first check
    $SQLCommandParams = @{
        DatabaseName    = "master"
        InstanceName    = $instanceName
        Query           = @'

        -- table for final results
        declare @finalAssesment table (
            CheckResult         int,            -- either 1 for a finding 0 for not a finding
            ResultValue         nvarchar(100),  -- what value was evaluated
            ResultDescripton    nvarchar(100)   -- check description
        )
                       
        declare
            @finding_condition_met  int
            ,@CheckResult           int
            ,@ResultValue           varchar(100)
            ,@ResultDescripton      varchar(100)
       
        -- finding condition is initalized to 0
        set @finding_condition_met = 0
       
        -- filter out internal system only principals
        ;with cte_Principals as
        (
            select *
            from (
                select *
                from (
                    SELECT p.name AS Principal,
                    p.type_desc AS Type,
                    sp.permission_name AS Permission,  
                    sp.state_desc AS State
                    FROM sys.server_principals p
                    INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id
                    WHERE sp.permission_name = 'CONTROL SERVER'
                    OR sp.state = 'W'
                ) MyPrincipals
                where Principal not like ('##MS_SchemaSigningCertificate%')
            ) FilteredLikePrincipal
            where Principal not in (
                '##MS_AgentSigningCertificate##'
               ,'##MS_PolicySigningCertificate##'
               ,'##MS_SmoExtendedSigningCertificate##'
               ,'##MS_SQLAuthenticatorCertificate##'
               ,'##MS_SQLReplicationSigningCertificate##'
               ,'##MS_SQLResourceSigningCertificate##'
            )
        )
        select @ResultValue = (count(*))
        from cte_Principals
       
        if(@ResultValue) != '0'
        begin
            set @finding_condition_met  = 1
            set @ResultDescripton       = 'Principal other than internal ones has control server permissions.'
        end
        else
        begin
            set @ResultDescripton       = 'No other principal other than internal ones, have control server permissions.'
        end
       
        insert into @finalAssesment
        Select
             [CheckResult]      = @finding_condition_met
            ,[ResultValue]      = @ResultValue
            ,[ResultDescripton] = @ResultDescripton
       
        select * from @finalAssesment
'@
    }

    # check 1
    $reachedInstance = [bool]
    $findingStatus   = "not_a_finding"
    $myCommentList   = @()
    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    try{
        $reachedInstance = $true
        $checkResults = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams -ErrorAction Stop
    }catch{
        $reachedInstance = $false
    }
   

    if($reachedInstance -eq $false){
        $findingStatus = "open"
         $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."

            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($myCommentList -join "`n")
            })
           
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
       
            if($DisplayStatus){
                $PSSTIG.GetFindingInfo(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                })
            }
    }else{
        $myCheckResults = @(
            [pscustomobject]@{Results = $checkResults.Rows.CheckResult ; ResultValue = $checkResults.Rows.ResultValue; ResultDescripton = $checkResults.Rows.ResultDescripton}
        )
   
        if($myCheckResults.Results -eq 1){
            $findingStatus = "open"
        }
   
        if($myCheckResults.Results -eq 0){
            $findingStatus = "not_a_finding"
        }
   
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "There is a total of '$($myCheckResults.ResultValue)' accounts that need to be addressed.")
        #$myCommentList += "'$SourceDataFrom' is used to document all sql logins that are memebers of 'sysadmin','securityadmin', or 'serveradmin' roles for instance '$($instanceName)'."

        $adminRoleScript    = $myScripts['script_02']
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $adminRoleScript
        }
   
        $checkResults   = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams
        $myContent      = @(Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ",")
        $headingString  = [string]
        $headingsList   = @("RecordID","InstanceName","Memeber","Type","Role","Description")
        $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')
   
        if(0 -eq [int]$myContent.count){
            Add-Content -Path $SourceDataFrom -Value $headingString
        }
   
        if(0 -eq [int]$myContent.count){
            [int]$recordID = 1
        }else{
            [int]$recordID = [int]$myContent.RecordID[-1]+1
        }
       
        $myEntriesList  = @()
        foreach($accountName in $checkResults){
            $entryString    = [string]
            $myEntry        = @("$recordID","$($accountName.InstanceName)","$($accountName.Member)","$($accountName.Type)","$($accountName.Role)","$($accountName.Description)")
            $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
            $myEntriesList += $entryString
            $recordID       = ($recordID) + 1
        }
   
        $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
        $myCurrenEntriesTable   = $myContent | Group-Object -Property 'InstanceName' -AsHashTable
   
        $nullDescriptionList    = @()
        $noEntryExistsList      = @()
        $noAccountNameExistList = @()
        foreach($newEntry in $newEntriesList){
            $newEntryInstanceName = $newEntry.InstanceName
            $currentEntriesObject = $myCurrenEntriesTable.$newEntryInstanceName
           
            # are there entries for this hostname?
            $instanceNameEntryExists = [bool]
            if($currentEntriesObject.InstanceName.count -eq 0){
                $instanceNameEntryExists = $false
            }else{
                $instanceNameEntryExists = $true
            }
   
            # if the entry doesnt already exist, then it gets added
            if(-not($instanceNameEntryExists)){
                $myEntry = ('{0},"{1}","{2}","{3}","{4}","{5}"' -f
                    $newEntry.RecordID,
                    $newEntry.InstanceName,
                    $newEntry.Memeber,
                    $newEntry.Type,
                    $newEntry.Role,
                    $newEntry.Description)
                Add-Content -Path $SourceDataFrom -Value $myEntry
                $findingStatus      = "open"
                $noEntryExistsList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
            # is the name of the account in the list?
            $accountNameExists = [bool]
            if(-not($currentEntriesObject.Memeber -contains $newEntry.Memeber)){
                $accountNameExists = $false
            }else{
                $accountNameExists = $true
            }
   
            if( $accountNameExists -eq $false){
                $findingStatus          = "open"
                $noAccountNameExistList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
   
            $currentEntryCheck = $currentEntriesObject |
                Select-Object -Property @('Memeber','Description') |
                Where-Object {$_.Memeber -eq ($newEntry.Memeber)}
   
            $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
           
            if($entryDescriptionIsNUll){
                $findingStatus          = "open"
                $nullDescriptionList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
        }
   
        if($findingStatus -eq "open"){
            if($nullDescriptionList.count -gt 0){
                $myCommentList += "All members need to be documented with a description, the following members are missing a description:"
                $myNullMembersList = ($nullDescriptionList | Select-Object -Property Memeber).Memeber
                $myMembersString = @()
                foreach($member in $myNullMembersList){
                    if($member -eq 'sa'){
                        $myMembersString += ("   '{0}' is missing a description. Note: 'sa' accounts need to be renamed and disabled." -f $member)
                    }else{
                        $myMembersString += ("   '{0}' is missing a description." -f $member)
                    }
                }
                $myMembersString = $myMembersString -join "`n"
                $myCommentList += $myMembersString
            }
        }else{
            $myCommentList += "'$SourceDataFrom' is used to document all role memebers for instance'$($instanceName)'."
        }
   
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
   
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}