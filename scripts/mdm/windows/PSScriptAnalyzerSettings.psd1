@{
    ExcludeRules = @(
        # The scripts log with Write-Host on purpose. An MDM captures the
        # console, and the success stream stays free for function results.
        'PSAvoidUsingWriteHost',
        # The Remove-* and Set-* helpers are internal to two scripts that an
        # MDM runs without a prompt. ShouldProcess has no caller here.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
