Function Show-Message{
    param (
       [string]$method_name,
       [string]$message,
       [string]$message_type
    )
    $output_message = "[{0}]:: {1}" -f
    $method_name,
    $message

    $message_color = switch($message_type){
        'feed_back' {
            "Cyan"
        }
        'info'      {
            "Yellow"
        }
        'failed'   {
            "Red"
        }
        'success'   {
            "Green"
        }
        default     {
            Write-Host "message type '$message_type' is not defined" -ForegroundColor "red"
            $null
        }
    }

    if($null -ne $message_color){
        Write-Host $output_message -ForegroundColor $message_color
    }
}

Function Show-Banner {
Clear-Host
$Banner_Logo = `
"     ___         ___           ___                                   ___     
    /  /\       /  /\         /  /\          ___       ___          /  /\    
   /  /::\     /  /:/_       /  /:/_        /  /\     /  /\        /  /:/_   
  /  /:/\:\   /  /:/ /\     /  /:/ /\      /  /:/    /  /:/       /  /:/ /\  
 /  /:/~/:/  /  /:/ /::\   /  /:/ /::\    /  /:/    /__/::\      /  /:/_/::\ 
/__/:/ /:/  /__/:/ /:/\:\ /__/:/ /:/\:\  /  /::\    \__\/\:\__  /__/:/__\/\:\
\  \:\/:/   \  \:\/:/~/:/ \  \:\/:/~/:/ /__/:/\:\      \  \:\/\ \  \:\ /~~/:/
 \  \::/     \  \::/ /:/   \  \::/ /:/  \__\/  \:\      \__\::/  \  \:\  /:/ 
  \  \:\      \__\/ /:/     \__\/ /:/        \  \:\     /__/:/    \  \:\/:/  
   \  \:\       /__/:/        /__/:/          \__\/     \__\/      \  \::/   
    \__\/       \__\/         \__\/                                 \__\/"

$line_break     =`
" `n`n.............................................................................................`n"
$build_details  = `
"
-- ToolName:    'PSSTIG'
-- Build:       '1.2.2'
-- Released:    '12-16-2023'   
-- Help
    - Documentation on how to create checklists can be found in .\Documentation\README.md
    - Reports created during the usage of this utility can be found in .\Reports
"
$output_msg = '{0}{1}{2}' -f
    $Banner_Logo,
    $line_break,
    $build_details
Write-host $output_msg -ForegroundColor Cyan
}
Show-Banner

Function Get-ScriptPath {
    $PSScriptRoot_String = $PSScriptRoot
    $PathStringLength = ($PSScriptRoot_String).Length
    # this removed the reference to the private folder
    $ModulePath  = $PSScriptRoot_String.Substring(0,($PathStringLength -7))
    $ModulePath
}
Function Get-SmartCardCred{
    [cmdletbinding()]
    param()
       
    $SmartCardCode = @"
    // Copyright (c) Microsoft Corporation. All rights reserved.
    // Licensed under the MIT License.
   
    using System;
    using System.Management.Automation;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;
   
   
    namespace SmartCardLogon{
   
        static class NativeMethods
        {
   
            public enum CRED_MARSHAL_TYPE
            {
                CertCredential = 1,
                UsernameTargetCredential
            }
   
            [StructLayout(LayoutKind.Sequential)]
            internal struct CERT_CREDENTIAL_INFO
            {
                public uint cbSize;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
                public byte[] rgbHashOfCert;
            }
   
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredMarshalCredential(
                CRED_MARSHAL_TYPE CredType,
                IntPtr Credential,
                out IntPtr MarshaledCredential
            );
   
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CredFree([In] IntPtr buffer);
   
        }
   
        public class Certificate
        {
   
            public static PSCredential MarshalFlow(string thumbprint, SecureString pin)
            {
                //
                // here we set the structured data
                //
                NativeMethods.CERT_CREDENTIAL_INFO certInfo = new NativeMethods.CERT_CREDENTIAL_INFO();
                certInfo.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.CERT_CREDENTIAL_INFO));
   
                //
                // Locate the certificate in the certificate store
                //
                X509Certificate2 certCredential = new X509Certificate2();
                X509Store userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                userMyStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                userMyStore.Close();
   
                if (certsReturned.Count == 0)
                {
                    throw new Exception("Unable to find the specified certificate.");
                }
   
                //
                // marshal the cert
                //
                certCredential = certsReturned[0];
                certInfo.rgbHashOfCert = certCredential.GetCertHash();
                int size = Marshal.SizeOf(certInfo);
                IntPtr pCertInfo = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(certInfo, pCertInfo, false);
                IntPtr marshaledCredential = IntPtr.Zero;
                bool result = NativeMethods.CredMarshalCredential(NativeMethods.CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);
   
                string certBlobForUsername = null;
                PSCredential psCreds = null;
   
                if (result)
                {
                    certBlobForUsername = Marshal.PtrToStringUni(marshaledCredential);
                    psCreds = new PSCredential(certBlobForUsername, pin);
                }
   
                Marshal.FreeHGlobal(pCertInfo);
                if (marshaledCredential != IntPtr.Zero)
                {
                    NativeMethods.CredFree(marshaledCredential);
                }
               
                return psCreds;
            }
        }
    }
"@       
       
    Add-Type -TypeDefinition $SmartCardCode -Language CSharp
    Add-Type -AssemblyName System.Security
       
    $ValidCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem 'Cert:\CurrentUser\My')
    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection($ValidCerts, 'Choose a certificate', 'Choose a certificate', 0)
       
    $Pin = Read-Host "Enter your PIN: " -AsSecureString
       
    Write-Output ([SmartCardLogon.Certificate]::MarshalFlow($Cert.Thumbprint, $Pin))
}
Function ConvertFrom-Hashtable {
    [CmdletBinding()]
    Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
        [hashtable]$MyHashtable
    )
    PROCESS {
        $results = @()

        $MyHashtable | ForEach-Object{
            $result = New-Object psobject;
            foreach ($key in $_.keys) {
                $result | Add-Member -MemberType NoteProperty -Name $key -Value $_[$key]
             }
             $results += $result;
         }
        return $results
    }
}