function Resolve-AgentIdUri {
    param([Parameter(Mandatory)][string]$Uri)
    if ($Uri -match '^https?://') { return $Uri }
    # Relative URIs let Invoke-MgGraphRequest resolve the endpoint for the connected cloud (e.g. national clouds).
    return "$script:AgentIdGraphVersion/$($Uri.TrimStart('/'))"
}

function Invoke-AgentIdRawRequest {
    # The single point where the module talks to Microsoft Graph. Tests replace it by setting
    # $script:AgentIdGraphHandler to a scriptblock that takes (Uri, Headers).
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers
    )
    if ($script:AgentIdGraphHandler) {
        return & $script:AgentIdGraphHandler $Uri $Headers
    }
    $params = @{ Method = 'GET'; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($Headers) { $params.Headers = $Headers }
    Invoke-MgGraphRequest @params
}

function Get-AgentIdErrorStatus {
    # Classifies a failed Graph call:
    #   Denied       - 401/403: the signed-in identity lacks a permission or role
    #   NotSupported - 400/404: endpoint, cast or query option not available in this tenant/API version
    #   Error        - anything else (throttling after SDK retries, service errors, network)
    param([Parameter(Mandatory)]$ErrorRecord)

    if ($ErrorRecord.TargetObject -is [pscustomobject] -and $ErrorRecord.TargetObject.PSObject.Properties['AgentIdStatus']) {
        return $ErrorRecord.TargetObject   # already classified by Invoke-AgentIdGraphRequest
    }

    $code = $null
    try {
        $response = $ErrorRecord.Exception.Response
        if ($response -and $response.StatusCode) { $code = [int]$response.StatusCode }
    } catch { $code = $null }

    $message = @($ErrorRecord.Exception.Message, $ErrorRecord.ErrorDetails.Message) -join ' '
    if (-not $code) {
        switch -Regex ($message) {
            '\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges' { $code = 403; break }
            '\b401\b|Unauthorized'                                                   { $code = 401; break }
            '\b404\b|NotFound|Request_ResourceNotFound'                              { $code = 404; break }
            '\b400\b|BadRequest|Request_BadRequest|Request_UnsupportedQuery'         { $code = 400; break }
        }
    }

    $status = switch ($code) {
        401 { 'Denied' }
        403 { 'Denied' }
        400 { 'NotSupported' }
        404 { 'NotSupported' }
        default { 'Error' }
    }
    $short = ($message -replace '\s+', ' ').Trim()
    if ($short.Length -gt 300) { $short = $short.Substring(0, 300) + '...' }

    [pscustomobject]@{
        AgentIdStatus = $status
        StatusCode    = $code
        Message       = $short
    }
}

function Invoke-AgentIdGraphRequest {
    <#
    Sends a GET request to Microsoft Graph.
    -Uri accepts several candidate URIs; each is tried in order, moving to the next only when the previous one
    is NotSupported (400/404) - used where the documented shape of a request is uncertain. A Denied or Error
    result stops immediately, since another spelling of the same request won't fix a missing permission.
    -All follows @odata.nextLink and writes the items of every page to the pipeline; callers wrap the call
    in @() so that an empty result is an empty array rather than $null.
    Failures are re-thrown as an ErrorRecord whose TargetObject carries the classification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Uri,
        [switch]$All,
        [hashtable]$Headers
    )

    $failure = $null
    foreach ($candidate in $Uri) {
        try {
            $response = Invoke-AgentIdRawRequest -Uri (Resolve-AgentIdUri $candidate) -Headers $Headers
            if (-not $All) { return $response }

            $items = [System.Collections.Generic.List[object]]::new()
            while ($true) {
                foreach ($item in @($response.value)) {
                    if ($null -ne $item) { $items.Add($item) }
                }
                $next = $response.'@odata.nextLink'
                if (-not $next) { break }
                $response = Invoke-AgentIdRawRequest -Uri $next -Headers $Headers
            }
            return $items.ToArray()
        } catch {
            $failure = Get-AgentIdErrorStatus $_
            Write-Verbose "GET $candidate -> $($failure.AgentIdStatus) ($($failure.StatusCode)): $($failure.Message)"
            if ($failure.AgentIdStatus -ne 'NotSupported') { break }
        }
    }

    $exception = [System.Exception]::new("Microsoft Graph request failed ($($failure.AgentIdStatus)): $($failure.Message)")
    throw [System.Management.Automation.ErrorRecord]::new($exception, "AgentIdGraph.$($failure.AgentIdStatus)", 'NotSpecified', $failure)
}

function Test-AgentIdConnection {
    if ($script:AgentIdGraphHandler) { return }
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Run Connect-AgentIdAudit first (or Connect-MgGraph with the scopes listed in the README).'
    }
    if ($context.AuthType -eq 'Delegated' -and $context.Scopes) {
        $missing = $script:AgentIdCoreScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing) {
            Write-Warning ("The current Graph connection is missing scopes: {0}. Checks that depend on them will be reported as not evaluated." -f ($missing -join ', '))
        }
    }
}
