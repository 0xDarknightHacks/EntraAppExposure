<# .SYNOPSIS Runs the Entra App Exposure Pester suite. #>
#Requires -Modules Pester
Invoke-Pester -Path .\Tests -Output Detailed
