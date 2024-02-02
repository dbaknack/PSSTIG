@{
    RootModule = "./PSSTIG.psm1"
    ModuleVersion = '0.0.0'
    FunctionsToExport = @(
        "PSSTIGVIEWER",
        "PSSTIG",
        "PSSTIGManual",
        "Get-TargetData",
        "Invoke-UDFSQLCommand",
        "Invoke-Finding213988"
    )
}