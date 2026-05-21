function Invoke-CIPPStandardAuthenticatorMode {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) AuthenticatorMode
    .SYNOPSIS
        (Label) Set Microsoft Authenticator authentication mode
    .DESCRIPTION
        (Helptext) Sets the authenticationMode on every includeTarget of the Microsoft Authenticator authentication method policy. Use "push" to disable passwordless phone sign-in (mitigates MFA fatigue / push spam attacks where an attacker triggers an Authenticator push by knowing only the user's email address). Use "any" for Microsoft's default. Use "deviceBasedPush" to enforce passwordless-only.
        (DocsDescription) Controls the authenticationMode field of the Microsoft Authenticator authentication method configuration. Setting to "push" disables passwordless phone sign-in tenant-wide, closing the MFA-fatigue / push-spam attack vector where attackers can trigger pushes to a user's Authenticator app using only the user's email address. Microsoft Authenticator still functions as MFA after password entry. Setting to "any" restores Microsoft's default behavior (both push and passwordless allowed). Setting to "deviceBasedPush" enforces passwordless-only sign-in (advanced; only deploy if all users are passwordless-ready). The standard preserves all featureSettings (number matching, display-app-info, display-location) and only modifies authenticationMode on each existing includeTarget.
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
            "MFA Fatigue Mitigation"
            "CISA Guidance"
        EXECUTIVETEXT
            Closes a known MFA-fatigue attack pathway by disabling Microsoft Authenticator passwordless phone sign-in tenant-wide. Users continue to use Microsoft Authenticator for normal multifactor authentication after entering their password. Eliminates the scenario where attackers flood users with push notifications using only the user's email address.
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"creatable":false,"label":"Authentication mode","name":"standards.AuthenticatorMode.mode","options":[{"label":"Push only - disables passwordless phone sign-in (recommended)","value":"push"},{"label":"Any - Microsoft default, allows passwordless","value":"any"},{"label":"Passwordless only (deviceBasedPush) - advanced","value":"deviceBasedPush"}]}
        IMPACT
            Medium Impact
        ADDEDDATE
            2026-05-21
        POWERSHELLEQUIVALENT
            Invoke-MgGraphRequest -Method PATCH -Uri https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator -Body @{includeTargets=@(@{id='all_users';targetType='group';isRegistrationRequired=$false;authenticationMode='push'})}
        RECOMMENDEDBY
            "CISA MFA Fatigue Mitigation"
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>

    param($Tenant, $Settings)

    # Resolve and validate the desired mode (Settings.mode can be an autoComplete object or a plain string)
    $DesiredMode = if ($Settings.mode.value) { $Settings.mode.value } else { $Settings.mode }
    $ValidModes = @('push', 'any', 'deviceBasedPush')

    if ([string]::IsNullOrEmpty($DesiredMode) -or $DesiredMode -notin $ValidModes) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: invalid or missing 'mode' setting (got '$DesiredMode'). Expected one of: $($ValidModes -join ', ')" -sev Error
        return
    }

    # Fetch current Microsoft Authenticator policy
    try {
        $CurrentState = New-GraphGetRequest -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator' -tenantid $Tenant
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: could not read the Microsoft Authenticator policy. Error: $ErrorMessage" -sev Error
        return
    }

    $TargetCount = ($CurrentState.includeTargets | Measure-Object).Count
    if ($TargetCount -eq 0) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: Microsoft Authenticator policy has no includeTargets. Nothing to enforce." -sev Warn
        return
    }

    $MismatchedTargets = @($CurrentState.includeTargets | Where-Object { $_.authenticationMode -ne $DesiredMode })
    $StateIsCorrect = $MismatchedTargets.Count -eq 0

    # Remediate
    if ($Settings.remediate -eq $true) {
        if ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: already '$DesiredMode' on all $TargetCount includeTargets." -sev Info
        } else {
            try {
                # Rebuild includeTargets preserving id / targetType / isRegistrationRequired; set authenticationMode to desired value
                $NewIncludeTargets = @(
                    foreach ($t in $CurrentState.includeTargets) {
                        [pscustomobject]@{
                            id                     = $t.id
                            targetType             = $t.targetType
                            isRegistrationRequired = if ($null -ne $t.isRegistrationRequired) { [bool]$t.isRegistrationRequired } else { $false }
                            authenticationMode     = $DesiredMode
                        }
                    }
                )

                $PatchBody = @{
                    '@odata.type'  = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'
                    includeTargets = $NewIncludeTargets
                } | ConvertTo-Json -Depth 10 -Compress

                $null = New-GraphPostRequest -tenantid $Tenant -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator' -Type PATCH -Body $PatchBody -ContentType 'application/json'

                Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: set authenticationMode to '$DesiredMode' across $($NewIncludeTargets.Count) includeTarget(s)." -sev Info
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: failed to set authenticationMode to '$DesiredMode'. Error: $ErrorMessage" -sev Error
            }
        }
    }

    # Alert
    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode: authenticationMode is '$DesiredMode' as expected." -sev Info
        } else {
            $ActualModes = ($CurrentState.includeTargets | ForEach-Object { "$($_.id)=$($_.authenticationMode)" }) -join '; '
            Write-StandardsAlert -message "Microsoft Authenticator authenticationMode drifted from expected '$DesiredMode'. Current: $ActualModes" -object $CurrentState -tenant $Tenant -standardName 'AuthenticatorMode' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorMode drift: expected '$DesiredMode', found $ActualModes" -sev Warn
        }
    }

    # Report
    if ($Settings.report -eq $true) {
        Add-CIPPBPAField -FieldName 'AuthenticatorMode' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $Tenant
        $CurrentValue = @{
            authenticationModes = @($CurrentState.includeTargets | ForEach-Object {
                @{ id = $_.id; authenticationMode = $_.authenticationMode }
            })
        }
        $ExpectedValue = @{
            authenticationModes = @(@{ id = '<all includeTargets>'; authenticationMode = $DesiredMode })
        }
        Set-CIPPStandardsCompareField -FieldName 'standards.AuthenticatorMode' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -Tenant $Tenant
    }
}
