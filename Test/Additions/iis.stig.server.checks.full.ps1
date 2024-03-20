#region Get-IISSTIGCheck cmdlet
# function Get-IISSTIGCheck
# {
#     [CmdletBinding()]
#     [outputtype('PSCustomObject[]')]
#     Param
#     (
#         [Parameter(Position = 0)]
#         [ValidateNotNullOrEmpty()]
#         [string[]]
#         $VID
#     )

Function Get-TargetData{
    param(
        [string]$CheckListName,
        [psobject]$Session
    )
    $myCheckListFolderPath  = $PSSTIG.Configuration.Folders.CheckLists.Path
    $myCheckListFile        = Get-ChildItem -Path $myCheckListFolderPath -Filter "$CheckListName.cklb"

    $myCheckListData = $PSSTIG.GetCheckListData(@{
        CheckListName = $CheckListName
    })

    $technologyArea = switch($PSSTIG.PlatformParameters.OS){"onWindows" {"Windows OS"}}

    $myResults = Invoke-Command -Session $Session -ScriptBlock {
        $MACAddress     = (Get-NetAdapter)[0] | Select-Object MacAddress
        $IPv4           = (Get-NetIPConfiguration)[0] | Select-Object IPv4Address
        $FQDN           = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
        $HostName       = HostName
        $myResults = @{
            MACAddress = $MACAddress
            IPV4        = $IPv4
            FQDN        = $FQDN
            HostName    = $HostName
        }
        $myResults
    }
    $myResults.Add("TechnologyArea",$technologyArea)

    $myTargetData                   = $myCheckListData.target_data
    $myTargetData.host_name         = $myResults.HostName
    $myTargetData.ip_address          = $myResults.IPV4.IPv4Address.IPAddress
    $myTargetData.mac_address       = $myResults.MACAddress.MacAddress
    $myTargetData.technology_area   = $technologyArea
    $myTargetData.fqdn              = $myResults.FQDN
    $myCheckListData.target_data    = $myTargetData

    $myCheckListDataConverted = $myCheckListData | ConvertTo-Json -Depth 5
    Set-Content -path  $myCheckListFile.FullName -Value $myCheckListDataConverted
}

function Get-NotEmpty{
    param(
        [psobject]$Object
    )


$Empty = $Object
if (![string]::IsNullOrEmpty($Empty)) {
    $Empty = $True
}
Else{
    $Empty = $False
}

Return $Empty 
}

 
$computername = ''
$COMPUTER  = '' 
$computername = $env:computername
$COMPUTER  = $env:computername
$website = 'Server'

$filename = 'NIPRNET_$COMPUTER_IIS10Server.csv'

$filename = "NIPRNET_" + $($COMPUTER) + "_IIS10_" + $($Website) + ".csv"
$filename


$remoteSession = New-PSSession -ComputerName $computername
$cs = New-CimSession -ComputerName $computername


$Checks = @(

    [pscustomobject]@{VID='V-218784';Check=@('Web Administration is performed at the console.')}
    [pscustomobject]@{VID='V-218785';Check=@('W3C'),@('ETW,File'),@('Date,Time,ClientIP,UserName,Method,URIQuery,ProtocolStatus,Referer')}
    [pscustomobject]@{VID='V-218786';Check=@('W3C'),@('ETW,File')}
    [pscustomobject]@{VID='V-218787';Check=@('Verify client does not reflect the IP address of the proxy server.')}
    [pscustomobject]@{VID='V-218788';Check=@('W3C'),@('Connection RequestHeader'),@('Warning RequestHeader')}
    [pscustomobject]@{VID='V-218789';Check=@('W3C'),@('UserAgent,UserName,Referer'),@('Authorization RequestHeader'),@('Content-Type ResponseHeader')}
    [pscustomobject]@{VID='V-218790';Check=@('NT AUTHORITY\SYSTEM FullControl'),@('BUILTIN\Administrators FullControl')}
    [pscustomobject]@{VID='V-218791';Check='System location is backed up by Nutanix'}
    [pscustomobject]@{VID='V-218792';Check='The applications user management is accomplished by Active Directory(AD).'}
    [pscustomobject]@{VID='V-218793';Check=''}
    [pscustomobject]@{VID='V-218794';Check='False'}
    [pscustomobject]@{VID='V-218795';Check=''}
    [pscustomobject]@{VID='V-218796';Check='bidenj','DefaultAccount','R.Svr','X_Admin'}
    [pscustomobject]@{VID='V-218797';Check=''}
    [pscustomobject]@{VID='V-218798';Check=@('.exe','.dll','.com','','.bat','.csh')}
    [pscustomobject]@{VID='V-218799';Check=@('False')}
    [pscustomobject]@{VID='V-218800';Check=''}
    [pscustomobject]@{VID='V-218801';Check='0'}
    [pscustomobject]@{VID='V-218802';Check=@('Administrators-RES\R.SVR','Administrators-RES\RBAC - ACAS Administrators','Administrators-RES\RBAC - DatabaseAdmin','Administrators-RES\RBAC - ITSM Admin','Administrators-RES\svc-ivantiadmin_dev','Administrators-RES\svc-ivantiadmin_test','Administrators-RES\SVC-IvantiAdmin_Prod','Administrators-RES\SVC-IvantiAdmin_Test','Administrators-RES\svc-scoma','Administrators-RES\svc-scomaction','Administrators-x.adm','Guests-x.visitor','Performance Monitor Users-RES\svc-scomaction','Remote Desktop Users-RES\RES_Terminal_Users','System Managed Accounts Group-DefaultAccount','Users-NT AUTHORITY\Authenticated Users','Users-NT AUTHORITY\INTERACTIVE','Users-RES\Domain Users')}
    [pscustomobject]@{VID='V-218803';Check=' Web server management and the applications management functionality is separated.'}
    [pscustomobject]@{VID='V-218804';Check='UseCookies'}
    [pscustomobject]@{VID='V-218805';Check=@('UseCookies','20')}
    [pscustomobject]@{VID='V-218806';Check=''}
    [pscustomobject]@{VID='V-218807';Check=@('HMACSHA256','Auto')}
    [pscustomobject]@{VID='V-218808';Check='False'}
    [pscustomobject]@{VID='V-218809';Check='False'}
    [pscustomobject]@{VID='V-218810';Check='DetailedLocalOnly'}
    [pscustomobject]@{VID='V-218812';Check=@('False')}
    [pscustomobject]@{VID='V-218813';Check='Please See IIS Shutdown Procedure'}
    [pscustomobject]@{VID='V-218814';Check=@('CREATOR OWNER,268435456'),@('NT AUTHORITY\SYSTEM,FullControl'),@('BUILTIN\Administrators,FullControl'),@('BUILTIN\Users','ReadAndExecute, Synchronize'),@('NT SERVICE\TrustedInstaller','FullControl')}
    [pscustomobject]@{VID='V-218815';Check='Daily'}
    [pscustomobject]@{VID='V-218816';Check=@('NT AUTHORITY\SYSTEM','ReadAndExecute, Synchronize'),@('BUILTIN\Administrators','ReadAndExecute, Synchronize'),@('BUILTIN\Users','ReadAndExecute, Synchronize'),@('NT SERVICE\TrustedInstaller','FullControl'),@('APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES','ReadAndExecute, Synchronize'),@('APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES','ReadAndExecute, Synchronize')}
    [pscustomobject]@{VID='V-218817';Check=@('ActivID ActivClient x64 7.2.1','Axway Desktop Validator 5.1','DATT 1.4.44','IIS URL Rewrite Module 2 7.2.1980','iisnode for iis 7.x (x64) full 0.2.26.0','Ivanti Service & Asset Manager 2023.2.0.2023090401','Microsoft Access database engine 2016 (English) 16.0.5044.1000','Microsoft Exchange Web Services Managed API 2.1 15.0.847.30','Microsoft SQL Server 2014 Management Objects  (x64) 12.0.2000.8','Microsoft System CLR Types for SQL Server 2014 12.0.2402.11','Microsoft Visual C++ 2008 Redistributable - x64 9.0.21022 9.0.21022','Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219 10.0.40219','Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030 11.0.61030','Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030 11.0.61030','Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.21005 12.0.21005','Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.21005 12.0.21005','Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005 12.0.21005','Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005 12.0.21005','Microsoft Visual C++ 2019 X86 Additional Runtime - 14.29.30135 14.29.30135','Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.29.30135 14.29.30135','Microsoft Visual C++ 2022 X64 Additional Runtime - 14.31.31103 14.31.31103','Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.31.31103 14.31.31103','Nessus Agent (x64) 10.0.0.20074','Node.js 18.16.0','Nutanix Checks & Prereqs 2.1.2.0','Nutanix Guest Agent 2.1.2.0','Nutanix Guest Tools Infrastructure Components Package 1 2.1.2.0','Nutanix Guest Tools Infrastructure Components Package 2 2.1.2.0','Nutanix Self Service Restore 2.1.2.0','Nutanix VM Mobility 1.1.6.18','Nutanix VSS Modules 1.1.0 1.1.0.0','SolarWinds Agent 2020.2.2361.5 120.2.2361.5','Trellix Agent 5.08.1002','Trellix Data Exchange Layer for TA 6.0.31021.0','Trellix Data Loss Prevention - Endpoint 11.10.200.162','Trellix Endpoint Security Firewall 10.7.0','Trellix Endpoint Security Platform 10.7.0','Trellix Endpoint Security Threat Prevention 10.7.0','Trellix Policy Auditor Agent 6.5.7','Trellix Solidifier 8.3.7.19','UniversalForwarder 8.2.2.0')}
    [pscustomobject]@{VID='V-218818';Check='False'}
    [pscustomobject]@{VID='V-218819';Check=@('enabled True','UriScavengerPeriod 120', 'maxResponseSize 262144')}
    [pscustomobject]@{VID='V-218820';Check='True'}
    [pscustomobject]@{VID='V-218821';Check=''}
    [pscustomobject]@{VID='V-218822';Check=@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client,1,0'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server,1,0')}
    [pscustomobject]@{VID='V-218823';Check=@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server,0,1'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client,1,0'),@('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server,1,0')}
    [pscustomobject]@{VID='V-218824';Check='False'}
    [pscustomobject]@{VID='V-218825';Check=@("allow *,","deny ?,")}
    [pscustomobject]@{VID='V-218826';Check='4294967295'}
    [pscustomobject]@{VID='V-218827';Check=@('enabled True','max-age 0', 'includeSubDomains True', 'redirectHttpToHttps True')}
    [pscustomobject]@{VID='V-228572';Check='False'} # The IIS web server is not running SMTP relay services, this is Not Applicable.
    [pscustomobject]@{VID='V-241788';Check=@('1')} # Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name DisableServerHeader -Value 1
    [pscustomobject]@{VID='V-241789';Check=@('X-Powered-By'),@('ASP.NET')}  
    [pscustomobject]@{VID='V-218735';Check=@('InProc')}
    [pscustomobject]@{VID='V-218736';Check=@('UseCookies')}
    [pscustomobject]@{VID='V-218737';Check=@('Ssl')}
    [pscustomobject]@{VID='V-218738';Check=@('Ssl')}
    [pscustomobject]@{VID='V-218739';Check=@('W3C'),@('ETW,File')}
    [pscustomobject]@{VID='V-218740';Check=@('Please See SSP')}
    [pscustomobject]@{VID='V-218741';Check=@('W3C'),@('Connection RequestHeader'),@('Warning RequestHeader')}
    [pscustomobject]@{VID='V-218742';Check=@('W3C'),@('UserAgent,UserName,Referer'),@('Authorization RequestHeader'),@('Content-Type ResponseHeader')}
    [pscustomobject]@{VID='V-218743';Check=@('.exe','.dll','.com','','.bat','.csh')}
    [pscustomobject]@{VID='V-218744';Check=@(‘ScriptHandlerFactory *.asmx Enabled’), @(‘ScriptHandlerFactoryAppServices *_AppService.axd Enabled’), @(‘ScriptResource ScriptResource.axd Enabled’), @(‘profiler Orion/Skipi18n/Profiler/* Enabled’), @(‘ApiURIs-ISAPI-Integrated-4.0 api/* Enabled’), @(‘SapiURIs-ISAPI-Integrated-4.0 sapi/* Enabled’), @(‘ISAPI-dll *.dll Disabled’), @(‘AXD-ISAPI-4.0_64bit *.axd Enabled’), @(‘PageHandlerFactory-ISAPI-4.0_64bit *.aspx Enabled’), @(‘SimpleHandlerFactory-ISAPI-4.0_64bit *.ashx Enabled’), @(‘WebServiceHandlerFactory-ISAPI-4.0_64bit *.asmx Enabled’), @(‘HttpRemotingHandlerFactory-rem-ISAPI-4.0_64bit *.rem Enabled’), @(‘HttpRemotingHandlerFactory-soap-ISAPI-4.0_64bit *.soap Enabled’), @(‘aspq-ISAPI-4.0_64bit *.aspq Enabled’), @(‘cshtm-ISAPI-4.0_64bit *.cshtm Enabled’), @(‘cshtml-ISAPI-4.0_64bit *.cshtml Enabled’), @(‘vbhtm-ISAPI-4.0_64bit *.vbhtm Enabled’), @(‘vbhtml-ISAPI-4.0_64bit *.vbhtml Enabled’), @(‘TraceHandler-Integrated-4.0 trace.axd Enabled’), @(‘WebAdminHandler-Integrated-4.0 WebAdmin.axd Enabled’), @(‘AssemblyResourceLoader-Integrated-4.0 WebResource.axd Enabled’), @(‘PageHandlerFactory-Integrated-4.0 *.aspx Enabled’), @(‘SimpleHandlerFactory-Integrated-4.0 *.ashx Enabled’), @(‘WebServiceHandlerFactory-Integrated-4.0 *.asmx Enabled’), @(‘HttpRemotingHandlerFactory-rem-Integrated-4.0 *.rem Enabled’), @(‘HttpRemotingHandlerFactory-soap-Integrated-4.0 *.soap Enabled’), @(‘aspq-Integrated-4.0 *.aspq Enabled’), @(‘cshtm-Integrated-4.0 *.cshtm Enabled’), @(‘cshtml-Integrated-4.0 *.cshtml Enabled’), @(‘vbhtm-Integrated-4.0 *.vbhtm Enabled’), @(‘vbhtml-Integrated-4.0 *.vbhtml Enabled’), @(‘ScriptHandlerFactoryAppServices-Integrated-4.0 *_AppService.axd Enabled’), @(‘ScriptResourceIntegrated-4.0 *ScriptResource.axd Enabled’), @(‘AXD-ISAPI-4.0_32bit *.axd Enabled’), @(‘PageHandlerFactory-ISAPI-4.0_32bit *.aspx Enabled’), @(‘SimpleHandlerFactory-ISAPI-4.0_32bit *.ashx Enabled’), @(‘WebServiceHandlerFactory-ISAPI-4.0_32bit *.asmx Enabled’), @(‘HttpRemotingHandlerFactory-rem-ISAPI-4.0_32bit *.rem Enabled’), @(‘HttpRemotingHandlerFactory-soap-ISAPI-4.0_32bit *.soap Enabled’), @(‘aspq-ISAPI-4.0_32bit *.aspq Enabled’), @(‘cshtm-ISAPI-4.0_32bit *.cshtm Enabled’), @(‘cshtml-ISAPI-4.0_32bit *.cshtml Enabled’), @(‘vbhtm-ISAPI-4.0_32bit *.vbhtm Enabled’), @(‘vbhtml-ISAPI-4.0_32bit *.vbhtml Enabled’), @(‘TRACEVerbHandler * Enabled’), @(‘OPTIONSVerbHandler * Enabled’), @(‘ExtensionlessUrlHandler-ISAPI-4.0_32bit *. Enabled’), @(‘ExtensionlessUrlHandler-ISAPI-4.0_64bit *. Enabled’), @(‘ExtensionlessUrlHandler-Integrated-4.0 *. Enabled’), @(‘StaticFile * Enabled’)}
    [pscustomobject]@{VID='V-218745';Check=@(‘.asax False’) ,@(‘.ascx False’) ,@(‘.master False’) ,@(‘.skin False’) ,@(‘.browser False’) ,@(‘.sitemap False’) ,@(‘.config False’) ,@(‘.cs False’) ,@(‘.csproj False’) ,@(‘.vb False’) ,@(‘.vbproj False’) ,@(‘.webinfo False’) ,@(‘.licx False’) ,@(‘.resx False’) ,@(‘.resources False’) ,@(‘.mdb False’) ,@(‘.vjsproj False’) ,@(‘.java False’) ,@(‘.jsl False’) ,@(‘.ldb False’) ,@(‘.dsdgm False’) ,@(‘.ssdgm False’) ,@(‘.lsad False’) ,@(‘.ssmap False’) ,@(‘.cd False’) ,@(‘.dsprototype False’) ,@(‘.lsaprototype False’) ,@(‘.sdm False’) ,@(‘.sdmDocument False’) ,@(‘.mdf False’) ,@(‘.ldf False’) ,@(‘.ad False’) ,@(‘.dd False’) ,@(‘.ldd False’) ,@(‘.sd False’) ,@(‘.adprototype False’) ,@(‘.lddprototype False’) ,@(‘.exclude False’) ,@(‘.refresh False’) ,@(‘.compiled False’) ,@(‘.msgx False’) ,@(‘.vsdisco False’) ,@(‘.rules False’)}
    [pscustomobject]@{VID='V-218746';Check=@('False')}
    [pscustomobject]@{VID='V-218748';Check=@('https :443:'),@('http :80:')}
    [pscustomobject]@{VID='V-218749';Check=@('Ssl','SslNegotiateCert','SslRequireCert')}
    [pscustomobject]@{VID='V-218750';Check=@('')}
    [pscustomobject]@{VID='V-218751';Check=@('')}
    [pscustomobject]@{VID='V-218752';Check=@('')}
    [pscustomobject]@{VID='V-218753';Check=@('')}
    [pscustomobject]@{VID='V-218754';Check=@('')}
    [pscustomobject]@{VID='V-218755';Check=@('')}
    [pscustomobject]@{VID='V-218756';Check=@('')}
    [pscustomobject]@{VID='V-218757';Check=@('')}
    [pscustomobject]@{VID='V-218758';Check=@('')}
    [pscustomobject]@{VID='V-218759';Check=@('')}
    [pscustomobject]@{VID='V-218760';Check=@('')}
    [pscustomobject]@{VID='V-218761';Check=@('')}
    [pscustomobject]@{VID='V-218762';Check=@('')}
    [pscustomobject]@{VID='V-218763';Check=@('')}
    [pscustomobject]@{VID='V-218764';Check='Please See IIS Shutdown Procedure'}
    [pscustomobject]@{VID='V-218765';Check=@('')}
    [pscustomobject]@{VID='V-218766';Check=@('https :443:'),@('http :80:')}
    [pscustomobject]@{VID='V-218767';Check=@('')}
    [pscustomobject]@{VID='V-218768';Check=@('Ssl','SslNegotiateCert','SslRequireCert','Ssl128')}
    [pscustomobject]@{VID='V-218769';Check=@('True')}
    [pscustomobject]@{VID='V-218770';Check=@('False','False')}
    [pscustomobject]@{VID='V-218771';Check=@('')}
    [pscustomobject]@{VID='V-218772';Check=@('')}
    [pscustomobject]@{VID='V-218773';Check=@('')}
    [pscustomobject]@{VID='V-218774';Check=@('')}
    [pscustomobject]@{VID='V-218775';Check=@('True')}
    [pscustomobject]@{VID='V-218776';Check=@('')}
    [pscustomobject]@{VID='V-218777';Check=@('True')}
    [pscustomobject]@{VID='V-218778';Check=@(‘DefaultAppPool 00:05:00’), @(‘.NET v4.5 Classic 00:05:00’), @(‘.NET v4.5 00:05:00’), @(‘SolarWinds Orion Application Pool,00:05:00’)}
    [pscustomobject]@{VID='V-218779';Check=@('.cgi'), @('.pl'), @('.class'), @('.c'), @('.php'), @('.asp')}
    [pscustomobject]@{VID='V-218780';Check=@('False')}
    [pscustomobject]@{VID='V-218781';Check=@(‘False’),@(‘*.bak’), @(‘*.old’), @(‘*.temp’), @(‘*.tmp’), @(‘*.backup’), @(‘copy of*’)}
    [pscustomobject]@{VID='V-218782';Check=@('')}
    )

#endregion Get-IISSTIGCheck cmdlet

# $Checks.count



# Custom type to search for duplicates.
class STIG {
    [string] $VID
    [string] $Status
    [string] $Finding
    [string] $Computer
    [string] $Site

}

$STIGList = [System.Collections.Generic.List[STIG]]::new()

# Add a new instance...
$STIGList.Add([STIG]::new())

$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site}

$array = @() 
$check= @()
$BlankLine

Clear-Host
Write-Output '##########################'
$BlankLine
$BlankLine

$VID ='V-218784'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
$array = @() ;$array = "Web Administration is performed at the console."
$Status = 'Not_Applicable'
$STIG_Check 

$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218785'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
$array = @() ;$array = $array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").logformat 
$logExtFileFlags = (Get-WebConfiguration –filter system.applicationhost/sites/sitedefaults/logfile | 
Select-Object -ExpandProperty logExtFileFlags)
$flagArr = $logExtFileFlags.Split(",") |Sort-Object
$array = $array + $flagArr
if(compare-object  $check $array| where sideindicator -eq "=>"){$status = 'NotAFinding'}
else{$status='Open'}

$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218786'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = $array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").logformat 
$array = ($array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").logtargetw3c.Split(",") )|Sort-Object
if(compare-object ($array|sort) $check2 -SyncWindow 0 | where sideindicator -eq "=>")
{$status='Open'}
else{$status = 'NotAFinding'}

$VID
$check2
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218787'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Please See SSP" 
$status = 'NotReviewed'
$VID
$check2 = $check2 + $array
$check2
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218788'
[array]$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = $array + ((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").logformat)
$Empty = (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields").collection 
if (![string]::IsNullOrEmpty($Empty)) {
    $Empty = $False
}
Else{
    $Empty = $True
}
#$logExtFileFlags = (Get-WebConfiguration –filter system.applicationhost/sites/sitedefaults/logfile | 
#Select-Object -ExpandProperty logExtFileFlags)
#$flagArr = $logExtFileFlags.Split(",") |Sort-Object
#$array = $array + $flagArr
# if(compare-object  $check2 $array| where sideindicator -eq "=>"){$status = 'NotAFinding'}
# else{$status='Open'}
$array = $array + (((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields").collection | Select @{label="results";expression={($_.SourceName)+" "+$_.sourcetype}}).results)
if(compare-object  $check2 $array| where sideindicator -eq "=>"){$status='Open'}
else {$status = 'NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218789'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() 
$array = $array + ((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").logformat)

$logExtFileFlags = (Get-WebConfiguration –filter system.applicationhost/sites/sitedefaults/logfile | Select-Object -ExpandProperty logExtFileFlags)
#$flagArr = $logExtFileFlags.Split(",") |Sort-Object
#$array = $array + $flagArr
$logExtFileFlags | ? {($_.value -like 'UserName') -or ($_ -eq 'UserAgent') -or ($_ -eq 'Referer')}

$flagArr = $logExtFileFlags.Split(",") 
$array = $array + $flagArr | ? {($_ -like 'UserName') -or ($_ -eq 'UserAgent') -or ($_ -eq 'Referer')}
$array = $array + (((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields").collection | Select @{label="results";expression={($_.SourceName)+" "+$_.sourcetype}}).results)
if(compare-object $check2 $array -IncludeEqual| where sideindicator -eq "=="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$check
$check2
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);




$VID ='V-218790'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = ((get-acl (dir ((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").directory).replace("%SystemDrive%\","C:\")).FullName ).Access | select @{label="result";expression={$_.identityreference.value +" " + $_.filesystemrights}}).result | select -unique
if(compare-object $check.check $array -IncludeEqual| where sideindicator -eq "=="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$check.Check
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218791'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array= $array+"System location is backed up by Nutanix"
$array = $array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").directory
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218792'
$array = @() ;$array = "Please see SSP. "
$array = $array + "The application's user management is accomplished by Active Directory(AD)."
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$check2
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218793'
$array = @() ;$array = (Get-WmiObject -Class Win32_Product | select @{label="results";expression={$_.name+","+$_.version}}).results
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = "Accepted settings:  " + $array
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218794'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WindowsFeature web-application-proxy).installed -eq $false){"False"} else {(Get-WindowsFeature web-application-proxy).installed}
if($array -eq $check ){$status = 'Open'}
else {$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218795'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @()
$locations = "inetpub","Program Files\Common Files\System\msadc","Program Files (x86)\Common Files\System\msadc"; $array = foreach ($location in $locations) {(get-childitem C:\$location -recurse | ? {($_.name -like "*.exe") -or ($_.name -like "*.bat") -or ($_.name -like "*.js") -or ($_.name -like "*.json")}).fullname} ; $array = if($array -eq ""){'No Findings'} else {$array}
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218796'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Get-WmiObject -class win32_useraccount -filter "localaccount=True").name
if(compare-object  $check2 $array -IncludeEqual | where sideindicator -eq "=="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218797'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ; $array += (Get-WmiObject -Class Win32_Product | select @{label="results";expression={$_.name+","+$_.version}}).results ; 
if(compare-object $check2 $array -includeequal| where sideindicator -eq "=="){$status = 'Open'} elseif((compare-object $array $check -includeequal | where sideindicator -eq "==") -eq $null){$status = 'NotAFinding'}
$array += (Get-WindowsFeature | ? Installed -eq $true).displayname
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218798'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = ((Get-WebConfiguration "system.webServer/staticContent").collection).fileextension
if(compare-object $array $check -includeequal| where sideindicator -eq "=="){$status = 'Open'} elseif((compare-object $array $check -includeequal | where sideindicator -eq "==") -eq $null){$status = 'NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218799'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WindowsFeature Web-DAV-Publishing).installed -eq $false){"False"} else {(Get-WindowsFeature Web-DAV-Publishing).installed}
if($array -eq $check ){$status = 'Open'}
else {$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218800'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Get-ChildItem -path cert:\LocalMachine\My | ? hasprivatekey -eq $true | select @{label="results";expression={($_.dnsnamelist.punycode)+","+$_.issuer}}).results
$array3 = $array -notlike "*DOD*"; $array3 = $array3 -notlike "*LTMA*" ; $array3 = $array3 -notlike "*noradnorthcom*"; $array3 = $array3 -ne ","
if($array3.count -eq 0 ) {$status = 'NotAFinding'}
else{$status = 'Open'}
$VID
$array
$array2
$array3
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218801'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (get-psdrive | ? provider -like "*file*" | ? used -ne 0 | % {get-childitem $_.root -recurse -ErrorAction SilentlyContinue | ? {($_.fullname -like "*.java") -or ($_.fullname -like "*.jpp")}}).fullname ; $array= if($array.count -eq 0){$status='NotAFinding'} else{$array}
# if(compare-object $array $check  -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
# else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218802'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @()
$groups = (Get-WMIObject -Class Win32_Group -Filter "LocalAccount=True").Name
foreach ($group in $groups)
{
 $members = net localgroup $group | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
 foreach($member in $members){$array += $group+"-"+$member}
}
if(compare-object $check2 $array  -includeequal | where sideindicator -eq "=>"){$status = 'Open'}
else {$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218803'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Please See SSP. "
$array = $array + $check2
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218804'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Get-WebConfiguration "system.web/sessionstate").cookieless
if(compare-object $array $check2  -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218805'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ; $array += (Get-WebConfiguration "system.web/sessionstate").cookieless ; $array += (Get-WebConfiguration "system.web/sessionstate").timeout.totalminutes
if((compare-object $check2 $array  -includeequal | where sideindicator -eq "==").count -eq 2){$status='NotAFinding'}
elseif((compare-object $array $check  -includeequal | where sideindicator -eq "==") -eq $null ) {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218806'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Please provide documentation for disaster recovery methods for the IIS 10.0 web server in the event of the necessity for rollback."
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218807'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array= $array+(Get-WebConfiguration "system.web/machinekey").validation
$array= $array+(Get-WebConfiguration "system.web/machinekey").decryption
if((compare-object $check2 $array  -includeequal | where sideindicator -eq "==").count -eq 2){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218808'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WebConfiguration "system.webServer/directoryBrowse").enabled -eq $false){"False"} else {(Get-WebConfiguration "system.webServer/directoryBrowse").enabled}
if(compare-object $check2  $array -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check2
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218809'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\')
if(compare-object $check2  $array -includeequal | where sideindicator -eq "=="){$status = 'Not Applicable'}
else {$status = 'Open'}
If($status -eq 'Open'){$status = $status + " Further review is required"}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218810'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WebConfiguration "system.webServer/httperrors").errormode -eq $false){"False"} else {(Get-WebConfiguration "system.webServer/httperrors").errormode}
if(compare-object $check2 $array  -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


# $VID ='V-218811'
# $check = $Checks | Where-Object {$_.VID -eq $VID} 
# [array]$check2 = $check.check.split(",")|Sort
# $array = "Web Administration is performed at the console."
# $Status = 'Not_Applicable'
# $VID
# $array
# $Status
# $BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218812'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WindowsFeature Web-Mgmt-Service).installed -eq $false){"False"} else {(Get-WindowsFeature Web-Mgmt-Service).installed}
if($array -eq $check ) {$status='NotApplicable'}
else{$status = 'Open'}
write-output 'False','Not Applicable WindowsFeature Web-Mgmt-Service is not installed'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218813'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Please See IIS Shutdown Procedure"
if(compare-object $check2 $array  -includeequal | where sideindicator -eq "==") {$status = 'Open'}
else{$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218814'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
$array = @(); $array = ((get-acl c:\inetpub).Access | ? {($_.PropagationFlags -like "*none*") -or ($_.identityreference -like "*creator*")}| select @{label="results";expression={$_.identityreference.value+" "+$_.FileSystemRights}}).results
if(compare-object  $check $array| where sideindicator -eq "<="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$array
$check
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218815'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array += (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").period ; $array += (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile").truncateSize
if(compare-object $check2 $array  -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218816'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array = ((get-acl c:\windows\system32\inetsrv\inetmgr.exe).Access | select @{label="results";expression={$_.identityreference.value+" "+$_.FileSystemRights}}).results
if(compare-object $check $array | where sideindicator -eq "<="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218817'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Get-WmiObject -Class Win32_Product | select @{label="results";expression={$_.name+" "+$_.version}}).results
if(compare-object $check2 $array | where sideindicator -eq "=>") {$status='Open'}
else{$status = 'NotAFinding'}

$VID
$array|Sort-object
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);

$VID ='V-218818'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((test-path c:\web\printers) -eq $False){"False"} else {test-path c:\web\printers}
if(compare-object $array $check  -includeequal | where sideindicator -eq "=="){$status = 'Open'}
else {$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218819'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
#$array = ((get-item 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\').property | ? {($_ -eq "URIEnableCache") -or ($_ -eq "UriMaxUriBytes") -or ($_ -eq "UriScavengerPeriod")}).count
#if($array -lt 3){$status = 'Open'}
#else {$status ='NotAFinding'}
#$key = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\"
#$array
#$array2 = get-childItem -Recurse -Path $key|  get-RegItemPropValue  | ? {($_.Name -eq "URIEnableCache") -or ($_.Name -eq "UriMaxUriBytes") -or ($_.Name -eq "UriScavengerPeriod")}
#if($status = 'NotAFinding'){[array]$array = @();$array = $array +(Get-IISConfigSection -SectionPath "system.webServer/caching").RawAttributes| ? {($_ -eq "URIEnableCache") -or ($_ -eq "UriMaxUriBytes") -or ($_ -eq "UriScavengerPeriod")}}
#else{}

[array]$array = @();
$array = $array +(Get-IISConfigSection -SectionPath "system.webServer/caching").RawAttributes | ? {($_ -eq "URIEnableCache") -or ($_ -eq "UriMaxUriBytes") -or ($_ -eq "UriScavengerPeriod")}
If(Get-NotEmpty $array){
$status = 'Open'
$array = 'Expected value is null' }
elseif((compare-object $check2 $array  -includeequal | where sideindicator -eq "==").count -eq 3){$status = 'Open'}
else {$status ='NotAFinding'}
$Status
$VID
$array
$array2
$check
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);
$check2
$check2.sort

$array2

$VID ='V-218820'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WebConfiguration "system.webserver/asp/session").keepsessionidsecure -eq $false){"False"} 
else {(Get-WebConfiguration "system.webserver/asp/session").keepsessionidsecure}

if(compare-object $array $check -includeequal | where sideindicator -eq "==")
{$status='NotAFinding'}
else 
{$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218821'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check
If(test-path -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2') {
$array = @() ;$array = ((get-childitem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -recurse |
where {((($_.name -like "*SSL*") -or ($_.name -like "*TLS*")) -and (($_.name -like "*client*") -or ($_.name -like "*server*")))}).pspath.replace("Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE","HKLM:") |
 % {(get-itemproperty $_) | select @{label="results";expression={$_.PSpath.replace("Microsoft.PowerShell.Core\Registry::","")+","+$_.Enabled+","+$_.disabledbydefault}}}).results
if((compare-object $check2 $array  -includeequal | where sideindicator -eq "==").count -eq 10)
{$status='NotAFinding'}}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218822'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check
If(test-path -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2') {
$array = @() ;$array = ((get-childitem 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' -recurse | where {((($_.name -like "*SSL*") -or ($_.name -like "*TLS*")) -and (($_.name -like "*client*") -or ($_.name -like "*server*")))}).pspath.replace("Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE","HKLM:") | % {(get-itemproperty $_) | select @{label="results";expression={$_.PSpath.replace("Microsoft.PowerShell.Core\Registry::","")+","+$_.Enabled+","+$_.disabledbydefault}}}).results
if((compare-object $check2 $array  -includeequal | where sideindicator -eq "==").count -eq 10){$status='NotAFinding'}}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218823'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Local Accounts are reset by LAPS solution. Please see SSP"
$status = 'NotAFinding'
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218824'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ; $array += if((Get-WebConfiguration "system.webserver/security/isapicgirestriction").notlistedcgisallowed -eq $false){"False"} else {(Get-WebConfiguration "system.webserver/security/isapicgirestriction").notlistedcgisallowed} ; $array += if((Get-WebConfiguration "system.webserver/security/isapicgirestriction").notlistedIsapisallowed -eq $False){"False"} else {(Get-WebConfiguration "system.webserver/security/isapicgirestriction").notlistedIsapisallowed}
if(compare-object $check2  $array -includeequal | where sideindicator -eq "==") {$status = 'Open'}
else{$status='NotAFinding'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218825'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = ((Get-WebConfiguration "system.web/authorization").collection | select @{label="results";expression={$_.ElementTagName+" "+$_.Users+","+$_.Roles}}).results
$array3 = $array -notlike "*Administrator*"
if($array3 -ne ""){$status = 'Open'}
else {$status = 'NotAFinding'}
If(compare-object $check2 $array -includeequal | where sideindicator -eq "==") {$status2 = 'Matches'}
else{$status2 ='NoMatches'}

$VID
$check
$check2
$array3
$Status
$Status2
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218826'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = (Get-WebConfiguration "system.applicationhost/sites/sitedefaults/limits").maxconnections
if($array -gt 0){$status = 'NotAFinding'}
else {$status = 'Open'}
$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218827'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
[array]$names = @('enabled', 'max-age', 'includeSubDomains','redirectHttpToHttps')
[array]$array = @(); $array = $array + (((Get-WebConfiguration "system.applicationHost/sites/siteDefaults/hsts")).attributes) | ? {($_.name -eq "enabled") -or ($_.name -eq "max-age") -or ($_.name -eq "includeSubDomains") -or ($_.name -eq "redirectHttpToHttps")}|select @{label="results";expression={$_.Name+" "+$_.value}}.results
$MaxAge = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "max-age").value
if(compare-object $check2  $array -includeequal | where sideindicator -eq "==") {$status = 'NotAFinding'}
elseif ($MaxAge -gt 0) {$status = 'NotAFinding'}

else{$status = 'Open'}

$VID
$array 
$MaxAge 
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);




# Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "enabled" -value "True"
# Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "max-age" -value 1
# Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "includeSubDomains" -value "True"
# Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/hsts" -name "redirectHttpToHttps" -value "True"

(((Get-WebConfiguration "system.applicationHost/sites/siteDefaults/hsts")).attributes | select @{label="results";expression={$_.Name+" "+$_.value}}).results



$VID ='V-228572'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = if((Get-WebConfiguration "system.net/mailsettings/smtp/network").host -eq ""){'SMTP Not Configured'} 
else 
{(Get-WebConfiguration "system.net/mailsettings/smtp/network").host}

if($array -eq 'SMTP Not Configured'){$status = 'NotAFinding'}
else{$status = 'Open'}

$VID
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-241788'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name DisableServerHeader |Select-Object -Property DisableServerHeader
if(compare-object $check2  $array -includeequal | where sideindicator -eq "==") {$status = 'Open'}
else{$status = 'NotAFinding'}

$VID
$check
$array
$Status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);

$VID ='V-241789'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$IISConfig = Get-IISConfigSection -SectionPath system.webServer/httpProtocol
$httpProtocolSection = (Get-IISConfigSection -SectionPath system.webServer/httpProtocol)
$customHeadersCollection = $httpProtocolSection.GetCollection("customHeaders")
$customHeadersCollection = ($httpProtocolSection.GetCollection("customHeaders")) | 
                            Select-Object -Property RawAttributes

[array]$array2 = ($customHeadersCollection.RawAttributes).Values
if(compare-object $check2  $array2 -includeequal | where sideindicator -eq "==") {$status = 'Open'}
else{$status = 'NotAFinding'}

$VID
$status
$array2
$check 
$check2
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$STIGList | Export-Csv .\$filename -Append -NoTypeInformation
