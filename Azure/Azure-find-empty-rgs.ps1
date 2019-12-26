<#
    .SYNOPSIS
        Finds empty ResourceGroups in Azure

    .DESCRIPTION
        Finds empty resource groups across all Azure subscriptions

    .PARAMETERS
        None

    .EXAMPLE
        ./Azure-find-empty-rgs.ps1

    .DEPENDENCIES
        None

    .NOTES
        Version: 1.0
        Author: Scott Brewerton
        Creation Date:  20180125
#>

$AzureSubs = Get-AzureRmSubscription | Sort-Object -Property Name
$List = @()
Foreach ($Sub in $AzureSubs)
{
    Select-AzureSubscription -SubscriptionId $Sub.SubscriptionId
    Select-AzureRmSubscription -SubscriptionId $Sub.SubscriptionId
    $RGs = Get-AzureRmResourceGroup | Sort-Object -Property Name
    ForEach($RG in $RGs)
    {
        $Count = 0
        $Count = (Get-AzureRmResource -ResourceGroupName $RG.ResourceGroupName).Count
        If ($Count -eq 0)
        {
            $List += ($Sub.Name) + ", " + ($RG.ResourceGroupName)
        }
        Else
        {

        }
    }
}

$List