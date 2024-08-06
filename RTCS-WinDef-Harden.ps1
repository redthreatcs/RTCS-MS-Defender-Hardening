$asciiArt = @"
  _____               _    _______   _                             _                            
 |  __ \             | |  |__   __| | |                           | |                           
 | |__) |   ___    __| |     | |    | |__    _ __    ___    __ _  | |_                          
 |  _  /   / _ \  / _`  |     | |    | '_ \  | '__|  / _ \  / _` | | __|                         
 | | \ \  |  __/ | (_| |     | |    | | | | | |    |  __/ | (_| | | |_                          
 |_|__\_\  \___|  \__,_|     |_|    |_| |_|_|_|_    \___|  \__,_|  \__|         _   _           
  / ____|         | |                     / ____|                              (_) | |          
 | |       _   _  | |__     ___   _ __   | (___     ___    ___   _   _   _ __   _  | |_   _   _ 
 | |      | | | | | '_ \   / _ \ | '__|   \___ \   / _ \  / __| | | | | | '__| | | | __| | | | |
 | |____  | |_| | | |_) | |  __/ | |      ____) | |  __/ | (__  | |_| | | |    | | | |_  | |_| |
  \_____|  \__, | |_.__/   \___| |_|     |_____/   \___|  \___|  \__,_| |_|    |_|  \__|  \__, |
            __/ |                                                                          __/ |
            |___/                                                                          |___/

"@
                                                                                                                                                    
Write-Host $asciiArt -ForegroundColor Red

$inputMp = $(Read-Host "Do you want to optimize windows defender? (Yes/No)").ToLower()

if ($inputMp -eq "yes") {

    # Require elevation for script run
    Write-Output "Elevating privileges for this process"
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"")
        exit
    }

    Write-Host "Enabling Windows Defender Features..."

    Set-MpPreference -DisableRealtimeMonitoring $False

    Set-MpPreference -MAPSReporting Advanced

    Set-MpPreference -CheckForSignaturesBeforeRunningScan $True

    Set-MpPreference -DisableBehaviorMonitoring $False

    Set-MpPreference -DisableIOAVProtection $False

    Set-MpPreference -DisableScriptScanning $False

    Set-MpPreference -DisableRemovableDriveScanning $False

    Set-MpPreference -DisableBlockAtFirstSeen $False

    Set-MpPreference -PUAProtection 1

    Set-MpPreference -DisableArchiveScanning $False

    Set-MpPreference -DisableEmailScanning $False

    Set-MpPreference -EnableFileHashComputation $True

    Set-MpPreference -DisableEmailScanning $False

    Set-MpPreference -DisableSshParsing $False

    Set-MpPreference -DisableDnsParsing $False

    Set-MpPreference -DisableDnsOverTcpParsing $False

    Set-MpPreference -EnableDnsSinkhole $True

    Set-MpPreference -EnableNetworkProtection Enabled

    Set-MpPreference -CloudBlockLevel High

    Set-MpPreference -CloudExtendedTimeout 30

    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $False

    Set-MpPreference -IntelTDTEnabled 0
    
    Write-Host "Windows Defender optimization done!" -ForegroundColor Green

    Write-Host "Please wait while the signatures are updated"
    Update-MpSignature -UpdateSource MicrosoftUpdateServer
    Update-MpSignature -UpdateSource MMPC
    
} else {
    Write-Host "No optimization performed"
    Write-Host "We are done! Thank you :)"
}

$inputMp = $(Read-Host "Do you want to enable Defender Attack Surface Reduction rules? (Yes/No)`n").ToLower()

if ($inputMp -eq "yes") {
    
    Write-Host "Enabling Windows Defender Attack Surface Reduction Rules`n"

    #https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules

    Write-Host "Block abuse of exploited vulnerable signed drivers`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block Adobe Reader from creating child processes`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block all Office applications from creating child processes`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block credential stealing from the Windows local security authority subsystem (lsass.exe)`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block executable content from email client and webmail`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block execution of potentially obfuscated scripts`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block JavaScript or VBScript from launching downloaded executable content`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block Office applications from creating executable content`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block Office applications from injecting code into other processes`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block Office communication application from creating child processes`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block untrusted and unsigned processes that run from USB`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block use of copied or impersonated system tools`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Block Win32 API calls from Office macros`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "Use advanced protection against ransomware`n"
    Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled

    Write-Host "ASR update done!"  -ForegroundColor Green


} else {
    Write-Host "ASR not modified"
    Write-Host "We are done! Thank you :)"
}

# Status report

Get-MpComputerStatus | Out-File -FilePath .\report1.txt
Get-MpPreference | Out-File -FilePath .\report2.txt 
Get-MpThreat | Out-File -FilePath .\report3.txt
Get-MpThreatDetection | Out-File -FilePath .\report4.txt 
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids | Out-File -FilePath .\report5.txt
