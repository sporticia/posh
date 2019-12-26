<#
    .SYNOPSIS
        This script creates a random/unique NETBIOS valid string
    .DESCRIPTION
        Randomly builds a x16 character sting using only numbers and uppercase letters from the ASCII charset and returns it
    .PARAMETER
        Length. Currently set to only accept '16', but could be modified to be more useful/flexible (test case was specifically NETBIOS names)
    .EXAMPLE
        ./RandomString.ps1 16
    
    .DEPENDENCIES
        None
    
    .NOTES
        Version: 1.0
        Author: Scott Brewerton
        Creation Date:  20180214
#>
Param
(
    [Parameter(Mandatory=$True)]   
    [ValidateRange(16,16)] 
    [Int]$StrLength
)
Function RandomString ($StrLength)
{
    # Add numbers
    $Digits = 48..57
    # Add uppercase letters
    $UpperLetters = 65..90
    # Make random string by taking a random char and appending it to $TmpStr for the total length supplied
    $RNDString = Get-Random -Count $StrLength -Input ($Digits + $UpperLetters) | ForEach-Object -Begin { $TmpStr = $null } -Process {$TmpStr += [char]$_} -End {$TmpStr}
    Return $RNDString
}
RandomString 16