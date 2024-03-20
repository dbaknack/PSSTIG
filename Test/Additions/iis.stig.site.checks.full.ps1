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

$computername   = ''
$COMPUTER       = '' 
$computername   = $env:computername
$COMPUTER       = $env:computername
$filename       = ''
$remoteSession  = New-PSSession -ComputerName $computername
$cs             = New-CimSession -ComputerName $computername

# Custom type to search for duplicates.
class App {
    [string] $AppPoolName
    [string] $Path
}

$AppList = [System.Collections.Generic.List[App]]::new()

# Add a new instance...
$AppList.Add([App]::new())

# Now add to it.

foreach($site in $sm.Sites) {
    foreach ($app in $site.Applications) {

        $newRec = [App] @{AppPoolName = $app.ApplicationPoolName; Path = $app.Path}
        $AppList.Add($newRec)
    }
}
$AppList 

#  $AppList |ForEach-Object {$_.Properties | Group-Object { $_.AppPoolName } | Format-Table }


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
    [pscustomobject]@{VID='V-218744';Check=@(�ScriptHandlerFactory *.asmx Enabled�), @(�ScriptHandlerFactoryAppServices *_AppService.axd Enabled�), @(�ScriptResource ScriptResource.axd Enabled�), @(�profiler Orion/Skipi18n/Profiler/* Enabled�), @(�ApiURIs-ISAPI-Integrated-4.0 api/* Enabled�), @(�SapiURIs-ISAPI-Integrated-4.0 sapi/* Enabled�), @(�ISAPI-dll *.dll Disabled�), @(�AXD-ISAPI-4.0_64bit *.axd Enabled�), @(�PageHandlerFactory-ISAPI-4.0_64bit *.aspx Enabled�), @(�SimpleHandlerFactory-ISAPI-4.0_64bit *.ashx Enabled�), @(�WebServiceHandlerFactory-ISAPI-4.0_64bit *.asmx Enabled�), @(�HttpRemotingHandlerFactory-rem-ISAPI-4.0_64bit *.rem Enabled�), @(�HttpRemotingHandlerFactory-soap-ISAPI-4.0_64bit *.soap Enabled�), @(�aspq-ISAPI-4.0_64bit *.aspq Enabled�), @(�cshtm-ISAPI-4.0_64bit *.cshtm Enabled�), @(�cshtml-ISAPI-4.0_64bit *.cshtml Enabled�), @(�vbhtm-ISAPI-4.0_64bit *.vbhtm Enabled�), @(�vbhtml-ISAPI-4.0_64bit *.vbhtml Enabled�), @(�TraceHandler-Integrated-4.0 trace.axd Enabled�), @(�WebAdminHandler-Integrated-4.0 WebAdmin.axd Enabled�), @(�AssemblyResourceLoader-Integrated-4.0 WebResource.axd Enabled�), @(�PageHandlerFactory-Integrated-4.0 *.aspx Enabled�), @(�SimpleHandlerFactory-Integrated-4.0 *.ashx Enabled�), @(�WebServiceHandlerFactory-Integrated-4.0 *.asmx Enabled�), @(�HttpRemotingHandlerFactory-rem-Integrated-4.0 *.rem Enabled�), @(�HttpRemotingHandlerFactory-soap-Integrated-4.0 *.soap Enabled�), @(�aspq-Integrated-4.0 *.aspq Enabled�), @(�cshtm-Integrated-4.0 *.cshtm Enabled�), @(�cshtml-Integrated-4.0 *.cshtml Enabled�), @(�vbhtm-Integrated-4.0 *.vbhtm Enabled�), @(�vbhtml-Integrated-4.0 *.vbhtml Enabled�), @(�ScriptHandlerFactoryAppServices-Integrated-4.0 *_AppService.axd Enabled�), @(�ScriptResourceIntegrated-4.0 *ScriptResource.axd Enabled�), @(�AXD-ISAPI-4.0_32bit *.axd Enabled�), @(�PageHandlerFactory-ISAPI-4.0_32bit *.aspx Enabled�), @(�SimpleHandlerFactory-ISAPI-4.0_32bit *.ashx Enabled�), @(�WebServiceHandlerFactory-ISAPI-4.0_32bit *.asmx Enabled�), @(�HttpRemotingHandlerFactory-rem-ISAPI-4.0_32bit *.rem Enabled�), @(�HttpRemotingHandlerFactory-soap-ISAPI-4.0_32bit *.soap Enabled�), @(�aspq-ISAPI-4.0_32bit *.aspq Enabled�), @(�cshtm-ISAPI-4.0_32bit *.cshtm Enabled�), @(�cshtml-ISAPI-4.0_32bit *.cshtml Enabled�), @(�vbhtm-ISAPI-4.0_32bit *.vbhtm Enabled�), @(�vbhtml-ISAPI-4.0_32bit *.vbhtml Enabled�), @(�TRACEVerbHandler * Enabled�), @(�OPTIONSVerbHandler * Enabled�), @(�ExtensionlessUrlHandler-ISAPI-4.0_32bit *. Enabled�), @(�ExtensionlessUrlHandler-ISAPI-4.0_64bit *. Enabled�), @(�ExtensionlessUrlHandler-Integrated-4.0 *. Enabled�), @(�StaticFile * Enabled�)}
    [pscustomobject]@{VID='V-218745';Check=@(�.asax False�) ,@(�.ascx False�) ,@(�.master False�) ,@(�.skin False�) ,@(�.browser False�) ,@(�.sitemap False�) ,@(�.config False�) ,@(�.cs False�) ,@(�.csproj False�) ,@(�.vb False�) ,@(�.vbproj False�) ,@(�.webinfo False�) ,@(�.licx False�) ,@(�.resx False�) ,@(�.resources False�) ,@(�.mdb False�) ,@(�.vjsproj False�) ,@(�.java False�) ,@(�.jsl False�) ,@(�.ldb False�) ,@(�.dsdgm False�) ,@(�.ssdgm False�) ,@(�.lsad False�) ,@(�.ssmap False�) ,@(�.cd False�) ,@(�.dsprototype False�) ,@(�.lsaprototype False�) ,@(�.sdm False�) ,@(�.sdmDocument False�) ,@(�.mdf False�) ,@(�.ldf False�) ,@(�.ad False�) ,@(�.dd False�) ,@(�.ldd False�) ,@(�.sd False�) ,@(�.adprototype False�) ,@(�.lddprototype False�) ,@(�.exclude False�) ,@(�.refresh False�) ,@(�.compiled False�) ,@(�.msgx False�) ,@(�.vsdisco False�) ,@(�.rules False�)}
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
    [pscustomobject]@{VID='V-218778';Check=@(�DefaultAppPool 00:05:00�), @(�.NET v4.5 Classic 00:05:00�), @(�.NET v4.5 00:05:00�), @(�SolarWinds Orion Application Pool,00:05:00�)}
    [pscustomobject]@{VID='V-218779';Check=@('.cgi'), @('.pl'), @('.class'), @('.c'), @('.php'), @('.asp')}
    [pscustomobject]@{VID='V-218780';Check=@('False')}
    [pscustomobject]@{VID='V-218781';Check=@(�False�),@(�*.bak�), @(�*.old�), @(�*.temp�), @(�*.tmp�), @(�*.backup�), @(�copy of*�)}
    [pscustomobject]@{VID='V-218782';Check=@('')}
    )


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

#     Process{
#     [array]$check = @()
#     $check = $Checks | Where-Object {$_.VID -eq $VID}
#     }
#     return $check
# }

#endregion Get-IISSTIGCheck cmdlet

# $Checks.count

$array = @() 
$check= @()
$BlankLine = ''

Clear-Host
Write-Output '##########################'

$BlankLine
$BlankLine

$Sites = Get-IISSite
$Sites |Select Name
Foreach($Site in $Sites) {
$Website =  $Site.Name.replace(' ','')

$filename = "NIPRNET_" + $($COMPUTER) + "_IIS10_Site" + $($Website) + ".csv"
$filename

$VID ='V-218735'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array += (get-webconfiguration "system.web/sessionstate" -location $site).mode
if((compare-object $check2 $array  -includeequal | where sideindicator -eq "==")){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218736'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort

$Empty = (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields").collection 
if (![string]::IsNullOrEmpty($Empty)) {
    $Empty = $False
}
Else{
    $Empty = $True
}

$array = @() ;$array += (Get-WebConfiguration "system.web/sessionstate"-location $site).cookieless
if(compare-object $array $check2  -includeequal | where sideindicator -eq "=="){$status='NotAFinding'}
else {$status = 'Open'}

$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218737'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array += ((Get-WebConfiguration "system.webserver/security/access" -location $site).sslflags).split(",")
if(compare-object $check2 $array | where sideindicator -eq "=>"){$status='Open'}
else{$status = 'NotAFinding'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218738'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array += ((Get-WebConfiguration "system.webserver/security/access" -location $site).sslflags).split(",")
if(compare-object $check2 $array | where sideindicator -eq "=>"){$status='Open'}
else{$status = 'NotAFinding'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218739'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = $array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile" -location $site).logformat 
$array = ($array + (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile" -location $site).logtargetw3c.Split(",") )|Sort-Object
if(compare-object ($array|sort) $check2 -SyncWindow 0 | where sideindicator -eq "=>")
{$status='Open'}
else{$status = 'NotAFinding'}

$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218740'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort

$array = @(); $array += "Please See SSP"
if(compare-object $array $check2 | where sideindicator -eq "=>"){$status='Open'}
else{$status = 'NotAFinding'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);




$VID ='V-218741'
[array]$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = $array + ((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile" -location $site).logformat)
$Empty = (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields" -location $site).collection 
if (![string]::IsNullOrEmpty($Empty)) {
    $Empty = $False
}
Else{
    $Empty = $True
}

$array = $array + (((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields" -location $site).collection | Select @{label="results";expression={($_.SourceName)+" "+$_.sourcetype}}).results)
if(compare-object  $check2 $array -IncludeEqual| where sideindicator -eq "=="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218742'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() 
$array = $array + ((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile" -location $site).logformat)

#$logExtFileFlags 
$logExtFileFlags | ? {($_.value -like 'UserName') -or ($_ -eq 'UserAgent') -or ($_ -eq 'Referer')}

$flagArr = $logExtFileFlags.Split(",") 
$array = $array + $flagArr | ? {($_ -like 'UserName') -or ($_ -eq 'UserAgent') -or ($_ -eq 'Referer')}
$array = $array + (((Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile/customFields" -location $site).collection | Select @{label="results";expression={($_.SourceName)+" "+$_.sourcetype}}).results)
if(compare-object $check2 $array -IncludeEqual| where sideindicator -eq "=="){$status = 'NotAFinding'}
else {$status='Open'}
$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);


$VID ='V-218743'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array += ((Get-WebConfiguration "system.webServer/staticContent" -location $site).collection).fileextension
if((compare-object $array $check2 -includeequal | ? sideindicator -eq "==").count -eq 0 ){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218744'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.webserver/handlers" -location $site).collection | select @{label="results";expression={$_.name+" "+$_.path+" "+$_.allowPathInfo}}).results.replace("False","Enabled").replace("True","Disabled") |Sort-object
if((compare-object $array $check2 -includeequal | ? sideindicator -eq "==").count -eq 0 ){$status = 'Open'}
else{$status='NotAFinding'}
# $status = 'NotAFinding'
$VID
$array
$array2 = $array2 -replace("Enabled","False") -replace("Disabled","True")
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218745'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.webserver/security/requestfiltering/fileextensions" -location $site).collection | select @{label="results";expression={$_.fileextension+" "+$_.allowed}}).results
if((compare-object $array.sort $check2.sort -includeequal | ? sideindicator -eq "==").count -eq 0 ){$status='NotAFinding'}
else{$status = 'Open'}
# $status = 'NotAFinding'
$VID
$array2 = $array
$array = $array2 -replace("False","Blocked") -replace("True","Allowed")
$check2
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218746'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WindowsFeature Web-DAV-Publishing).installed -eq $false){"False"} else {"True"}
#if((compare-object $check2 $array -includeequal | ? sideindicator -eq "==").count -eq 0 ){$status='NotAFinding'}
#else{$status = 'Open'}
# $status = 'NotAFinding'
if($array -eq $check2 ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218748'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (get-webbinding $site | select @{label="Results";expression={$_.protocol+" "+$_.bindinginformation+" "+(Get-ChildItem -path cert:\LocalMachine\My | ? PSChildName -eq $_.certificateHash).subject}}).results
$status = 'NotAFinding'
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218749'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.webserver/security/access" -location $site).sslflags).split(",")
if((compare-object $check2 $array -includeequal | ? sideindicator -eq "==")){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check2
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218750'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
if((Get-WebConfiguration "system.webServer/security/authentication/anonymousAuthentication" -location $site).enabled -eq $false){$array = "False,"}else{$array3 = @();$groups2 = "Administrators","Backup Operators","Certificate Services","Distributed COM Users","Event Log Readers","Network Configuration Operators","Performance Log Users","Performance Monitor Users","Power Users","Print Operators","Remote Desktop Users","Replicator";$groups = (Get-WMIObject -Class Win32_Group -Filter "LocalAccount=True").Name;$groups = (compare-object $groups $groups2 -IncludeEqual | ? sideindicator -eq "==").inputobject;foreach ($group in $groups){$members = net localgroup $group | where {$_ -AND $_ -like "*(Get-WebConfiguration 'system.webServer/security/authentication/anonymousAuthentication' -location $site).username*"};foreach($member in $members){$array3 += $group+"-"+$member}} ; $array = "True,"+ (Get-WebConfiguration "system.webServer/security/authentication/anonymousAuthentication" -location $site).username +","+ $array3.count}

if($array2.split(",")[0] -eq "False"){$status='NotAFinding'}
elseif(($array.split(",")[0] -eq "True") -and ($array.split(",")[2] -eq 0)){$status='NotAFinding'}
else{$status = 'Open'} 
$VID
$array
$array3
$groups
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218751'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (get-webconfiguration "system.web/sessionstate" -location $site).mode
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218752'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (get-item "IIS:\Sites\$site").physicalpath
if($array2 -like "C:\*"){$status = 'Open'}
else {$status = 'NotAFinding'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218753'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration 'system.webserver/security/requestfiltering/requestlimits' -location $site).maxurl
if($array2 -lt 4097){$status='NotAFinding'}
else{$status='Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218754'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration 'system.webserver/security/requestfiltering/requestlimits' -location $site).maxallowedcontentlength
$status='NotAFinding'
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218755'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration 'system.webserver/security/requestfiltering/requestlimits' -location $site).maxquerystring
if($array2 -lt 2049){$status='NotAFinding'}
else{$status='Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218756'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration 'system.webserver/security/requestfiltering' -location $site).allowhighbitcharacters  -eq $false){"False"} else {"True"}
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218757'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration 'system.webserver/security/requestfiltering' -location $site).allowdoubleescaping  -eq $false){"False"} else {"True"}
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218758'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration 'system.webserver/security/requestfiltering/fileextensions' -location $site).allowunlisted  -eq $false){"False"} else {"True"}
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218759'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration "system.webServer/directoryBrowse" -location $site).enabled  -eq $false){"False"} else {"True"}
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218760'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration "system.webServer/httperrors" -location $site).errormode
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218761'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration 'system.web/compilation' -location $site).debug  -eq $false){"False"} else {"True"}
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218762'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @()
$apppools = (Get-WebConfiguration "system.applicationHost/applicationpools").collection.name
$apppools | %{$array += (get-item "IIS:\AppPools\$_").processmodel.idletimeout.totalminutes}
if(($array2 -gt 20).count -eq 0 ){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check2
$apppools
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218763'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration 'system.web/sessionstate' -location $site).timeout.totalminutes
if($array2 -eq $check ){$status='NotAFinding'}
elseif($array2 -lt $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218764'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array = "Please See IIS Shutdown Procedure"
if(compare-object $check2 $array  -includeequal | where sideindicator -eq "==") {$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218765'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration "system.applicationHost/sites/sitedefaults/logfile" -location $site).period
if($array2 -eq $check ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218766'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((get-item "IIS:\sites\$site").bindings.collection | select @{label="results";expression={$_.protocol+" "+$_.bindinginformation}}).results
$status = 'NotAFinding'
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218767'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (get-webbinding $site | select @{label="Results";expression={$_.protocol+" "+$_.bindinginformation+","+(Get-ChildItem -path cert:\LocalMachine\My | ? PSChildName -eq $_.certificateHash).subject}}).results
if($array2 -like "*OU=DoD*"){$status = 'NotAFinding'}
else {$status = 'Open'}
#$array = @() ;$array = (Get-ChildItem -path cert:\LocalMachine\My | ? hasprivatekey -eq $true | select @{label="results";expression={($_.dnsnamelist.punycode)+","+$_.issuer}}).results
#$array3 = $array -notlike "*DOD*"; $array3 = $array3 -notlike "*LTMA*" ; $array3 = $array3 -notlike "*noradnorthcom*"; $array3 = $array3 -ne ","
#if($array3.count -eq 0 ) {$status = 'NotAFinding'}
#else{$status = 'Open'}


$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218768'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.webserver/security/access" -location $site).sslflags).split(",")
if((compare-object $check2 $array -includeequal | ? sideindicator -eq "==")){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218769'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  if((Get-WebConfiguration 'system.webserver/asp/session' -location $site).keepsessionidsecure  -eq $false){"False"} else {"True"}
if($array -eq $check2 ){$status='NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check2
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218770'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ; $array += (Get-WebConfiguration 'system.web/httpcookies' -location $site).requiressl ;$array += (Get-WebConfiguration 'system.web/sessionstate' -location $site).compressionenabled
if((compare-object $check2 $array -includeequal | ? sideindicator -eq "==")){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check2
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218771'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @()
#$array += " "
$array += (Get-Website | select @{label="results";expression={$_.applicationpool}}).results
if(($array).count -eq ($array | select  -unique).count){$status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check2
$check
($array).count 
($array | select  -unique).count
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218772'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="results";expression={$_.name+" "+($_.recycling.periodicrestart.requests)}}).results
if(($array | % { $_.split(",")[1] | ? $_ -eq 0 }).count -eq 0){$Status='NotAFinding'}
else{$status = 'Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218773'
write-output "$VID Not currently checked"
# $check = $Checks | Where-Object {$_.VID -eq $VID} 
# [array]$check2 = $check.check.split(",")|Sort
# $array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="results";expression={$_.name+" "+($_.recycling.periodicrestart.memory)}}).results
# if(($array | % { $_.split(",")[1] | ? $_ -eq 0 }).count -eq 0){$Status='NotAFinding'}
# else{$status = 'Open'}




$VID ='V-218774'
write-output "$VID Not currently checked"
# $check = $Checks | Where-Object {$_.VID -eq $VID} 
# [array]$check2 = $check.check.split(",")|Sort
# $array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="Results";expression={$_.name+" "+($_.recycling.periodicrestart.privatememory)}}).results
# if(($array2 | % { $_.split(",")[1] | ? $_ -eq 0 }).count -eq 0){$Status='NotAFinding'}
# else{$status = 'Open'}




$VID ='V-218775'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (Get-WebConfiguration "system.applicationHost/applicationpools").collection.recycling.logeventonrecycle | % {$_ -split(",")}
$apps = ((Get-WebConfiguration "system.applicationHost/applicationpools").collection).count
$time = ($array -eq "time").count
$schedule = ($array -eq "schedule").count
$array = if($time -eq $schedule){$time -eq $apps}else {$false}
$array = $array -replace($true,"True") -replace($false,"False")
if($array -eq $check2){$status= 'NotAFinding'}
else {$status = 'Open'}
$VID
$array
$check2
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218776'
write-output "$VID Not currently checked"
# $check = $Checks | Where-Object {$_.VID -eq $VID} 
# [array]$check2 = $check.check.split(",")|Sort
# $array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="Results";expression={($_.processmodel.pingingenabled)}}).results
# if(($array -eq $False ).count -eq 0){$status= 'NotAFinding'}
# else{$status='Open'}




$VID ='V-218777'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="Results";expression={($_.failure.rapidfailprotection)}}).results
if(($array -eq $False ).count -eq 0){$status= 'NotAFinding'}
else{$status='Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);
# (Get-WebConfiguration "system.applicationHost/applicationpools").collection.failure.rapidfailprotection | % {$_ -split(",")}


$VID ='V-218778'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  ((Get-WebConfiguration "system.applicationHost/applicationpools").collection | select @{label="Results";expression={($_.name+" "+$_.failure.rapidFailProtectionInterval)}}).results
if((($array | % {[int]($_.split(",")[1]-replace(":00","")-replace("00:",""))  -gt 5 }) -eq $true).count -eq 0){$status = 'NotAFinding'}
else{$status='Open'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218779'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  (get-childitem -recurse (get-item "IIS:\Sites\$site").physicalpath | where {($_.fullname -like "*.cgi") -or ($_.fullname -like "*.pl") -or ($_.fullname -like "*.vbs") -or ($_.fullname -like "*.class") -or ($_.fullname -like "*.c") -or ($_.fullname -like "*.php") -or ($_.fullname -like "*.asp")}).fullname
if($array.count -eq 0 ){$status = 'NotAFinding'}
else{$status = 'Not_Reviewed'}
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218780'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @() ;$array += if((Get-WindowsFeature web-application-proxy).installed -eq $false){"False"} else {(Get-WindowsFeature web-application-proxy).installed}
if($array -eq $check ){$status = 'Open'}
else {$status='NotAFinding'}

$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218781'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")
$array = @() ;$array += if((Get-WindowsFeature web-cgi).installed -eq $false){"False"} else {(Get-WindowsFeature web-cgi).installed}
if($array -eq $check2[0] ){$status = 'NotApplicable'}
else {
$array = @(); $array +=  (get-childitem -recurse (get-item "IIS:\Sites\$site").physicalpath | where {($_.fullname -like "*.bak") -or ($_.fullname -like "*.old") -or ($_.fullname -like "*.tmp") -or ($_.fullname -like "*.temp") -or ($_.fullname -like "*.backup") -or ($_.fullname -like "*copy of*")}).fullname
$status = 'Not_Reviewed'}
$VID
$array
$check2
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);



$VID ='V-218782'
$check = $Checks | Where-Object {$_.VID -eq $VID} 
[array]$check2 = $check.check.split(",")|Sort
$array = @(); $array +=  'Banner is provided by application owner. Please validate each solution.'
$status = 'NotAFinding'
$VID
$array
$check
$status
$BlankLine;$newRec = [STIG] @{VID = $VID; Status = $Status; Finding = $Array; Computer = $Computer; Site = $Site};$STIGList.Add($newRec);

$STIGList | Export-Csv .\$filename -Append -NoTypeInformation

 }
