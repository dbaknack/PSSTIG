Function Invoke-Finding214046{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [boolean]$SkipNonFinding = $true,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        if(-not($skip)){
            $check = @{
                value = 2
                comments = @(
                    "The requirement emphasizes obscuring feedback of authentication information (e.g., displaying asterisks for passwords).",
                    "While DBAs can enforce security policies within the database, they do not control the user interface or feedback mechanisms.",
                    "The presentation layer (UI) handles feedback to users during authentication (e.g., displaying asterisks or other obfuscation techniques).",
                    "DBAs are not involved in UI design or user interaction, so they cannot directly influence how feedback is presented.",
                    "Therefore, the responsibility for implementing secure feedback mechanisms lies with UI designers, developers, and front-end engineers."
                )
            }
            
            # comment are being added to array
            $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
            $comments += "{0}" -f ' '
            $comments += "{0}" -f "Remarks:"
            $comments += "{0}" -f ($check.comments -join "`n")
            
            # set finding status
            $findingStatus = switch($check.value){
                0       {'not_a_finding'}
                1       {'open'}
                2       {'not_applicable'}
                default {'not_reviewed'}
            }
        }
    }
    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213963{
    param(
        [string]$HostName,
        [string]$FindingID,
        [string]$FolderPath,
        [string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        # get documentation
        # define the parameters
        $GetDocumentParams  = @{FolderPath = $FolderPath; FileName = $FileName}
        $SourcePath         = (Get-DocumentSource @GetDocumentParams)
        $ReadDocumentParams = @{DocumentSourcePath = $SourcePath}
        $myDocData          = Read-DocumentSource @ReadDocumentParams

        $SharedAccount = [pscustomobject]@{
            AccountName  = ""
        }
        # look in the documentation list for all host, not this host, in the given
        $HostEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $HostName -and $_.instanceName -eq $instanceName}
        if($null -eq $HostEntry){
            $DefaultData = $myDocData.Schema.DefaultValues
            if($myDocData.TotalEntries -eq 0){
                [int]$lastRecID =$DefaultData.RecID
            }else{
                [int]$lastRecID = (($myDocData.data)[-1]).RecID
            }

            foreach($item in $SharedAccount.AccountName){
                $lastRecID = $lastRecID + 1
                $InsertItem = [pscustomobject]@{
                    RecID           = $lastRecID
                    HostName        = $HostName
                    InstanceName    = $instanceName
                    AccountName     = $DefaultData.AccountName
                    isApproved      = $DefaultData.isApproved
                }
                $InsertString = '"{0}"' -f(@(
                $InsertItem.RecID
                $InsertItem.HostName
                $InsertItem.InstanceName
                $InsertItem.AccountName
                $InsertItem.isApproved) -join '","')

                Add-Content -path $SourcePath -Value $InsertString
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
        }

        # if anything documented comes back its not a finding
        $myDocData = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $HostName -and $_.instanceName -eq $InstanceName -and $_.isApproved -eq 'True'}
        $check = @{
            value       = 1
            comments    = @("Service account are using, while this is by some definition to an approved, process.",
                            "When doing administrative task, being able to use a service account should be possible.",
                            "By default, this will be an open finding until:",
                            "   we can document service account",
                            "   define some documentation on approved service account",
                            "   be able to audit when the service accounts are being used to make a change"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213985{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                "There still needs to be an audit file on this instance"
                "Solarwinds and/or Nutanix has the ability to provide some alerting capability."
                "for now this a finding, untill the alerts are set up."
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213984{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                "First, you need an existing audit log that will make use of some drive",
                "Then there needs to be an alert in place that will trigger at 75% used space"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213983{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                    "There needs to be documentation that defines the storage requirements for the audit file on all instances."
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213982{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                    "There is no centralized way to adminisert the audit files for all instances"
                    "One will need to be created, and documented"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213981{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 0
            comments    = @(
                    "There is documentation for all SQL instance configuration componentes."
                    "\\petencnfs04\CCRI_LIBRARY\\SysAd NIPRNET CM STIGS\\SOP_Library"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213942{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                    "There just need to be documentation that for this stig, we dont want to shutdown the instance"
                    "in the event that the drive for the audit log fills up"
                    "there also needs to be an audit created"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213941{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                    "There needs to be documentation about how to look in the audit log"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213953{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       = 1
            comments    = @(
                    "There is documentation about where SQL is installed"
                    "validation is required to make sure that no other stuff is installed along with with the sql engine components, so long theyre not considered shared components"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213931{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Make sure that the service account for all service account running SQL Service have registered SPINs"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213980{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  0
            comments    = @(
                    "There is documentation that define accounts allowed to execute external commands where allowed"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213959{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  0
            comments    = @(
                    "There is documentation of stored procedures for all instances. Add any that are currently missing if any."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213932{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  0
            comments    = @(
                    "There is a documented request for for new SQL Logins that are required as well as the permissions being requested"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213933{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "There are some service account that are shared, but approved to only be used to the extent that a task is required for an approved change"
                    "entried are captured in the audit log for each instance."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213951{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "hash of where the instance files are currently located needs to be created"
                    "there needs to be documentation about when something in the install directory is altered, how to do that"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Updating SQL Job Step .ps1 Files"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213950{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation that states that only some logins are enable to modify approvied things in the sql isntall locaiton"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Approved List of Account with Alter privilages"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213952{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation that defines what group has the ability to modify SQL Server Instances at the server level."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Approved server level Accounts."
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213936{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation that defines that the audit files contains"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Tracked Auditable events"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213986{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "When the instance has audit log, there needs to be entried in UTC time format."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Audit Log Configuration"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213955{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation of approved features must be created"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Instance Approved Features List"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213979{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation that defines what logins have the ALTER, DROP, REVOKE, and DENY permissions"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\DDF Accounts list"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213978{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation that defines access to details errors to only be accessible to members of a given group"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Accounts Role Based Access Description."
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213962{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation of approved port for SQL Instance and Features."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Approved SQL Ports List."
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213977{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation of the folder and files that SQL Service account have access to as well as permissions "
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Service File Access List"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213970{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation needs to be created that defines groups of users that are given access when theyre not technically part of the organization"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Service non-organizational users"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213937{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation needs to be created that defines groups of users allowed to maintaine the audit records"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Service Audit Group List"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213976{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Documentation needs to be created that defines Local Permissions for Accounts"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\Local Permissions List"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213975{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Servef configuration allows this setting"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Instances - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213961{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Server named pipes allowed or not"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Instances - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213960{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Server Access to linked servers"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Instances - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213939{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Server Audit"
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Audits - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213948{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Server Audit - SQL Server must protect its audit configuration from authorized and unauthorized access and modification."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Audits - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213940{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation for SQL Server Audit - SQL Server must initiate session auditing upon startup."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Audits - Configuration Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213972{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Storage - SQL Server must protect the confidentiality and integrity of all information at rest."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Storage"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213944{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Audit  - The audit information produced by SQL Server must be protected from unauthorized access, modification, and deletion."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Audit - COnfiguration"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213943{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Audit'"
                    "SQL Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Audit - COnfiguration"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213957{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Server Documentation'"
                    "Access to xp_cmdshell must be disabled, unless specifically required and approved."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Configuration - Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213974{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Server Documentation'"
                    "The Master Key must be backed up, stored offline and off-site."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Configuration - Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213973{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Server Documentation'"
                    "The Service Master Key must be backed up, stored offline and off-site."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Configuration - Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213958{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Server Documentation'"
                    "Access to CLR code must be disabled or restricted, unless specifically required and approved."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Configuration - Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213971{
    param(
        [string]$HostName,
        [string]$FindingID,
        #[string]$FolderPath,
        #[string]$FileName,
        [psobject]$Session,
        [boolean]$SkipNonFinding = $true,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        $check = @{
            value       =  1
            comments    = @(
                    "Validate documentation SQL Server Documentation'"
                    "SQL Server must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values."
                    "See \\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\SOP_Library\SQL Server Configuration - Documentation"
                )
        }
        
        # comment are being added to array
        $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
        $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
        $comments += "{0}" -f ' '
        $comments += "{0}" -f "Remarks:"
        $comments += "{0}" -f ($check.Comments -join "`n")
        
        # set finding status
        $findingStatus = switch($check.value){
            0       {'not_a_finding'}
            1       {'open'}
            default {'not_reviewed'}
        }
    }

    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
