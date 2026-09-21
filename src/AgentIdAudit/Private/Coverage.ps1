# Coverage records, for every kind of data the inventory collects, whether collection succeeded. Rules declare
# which coverage keys they depend on, and a rule whose inputs weren't collected is reported as "not evaluated"
# instead of silently producing no findings (or, worse, false ones such as "agent has no sponsor").

function New-AgentIdCoverage {
    return [ordered]@{}
}

function Initialize-AgentIdCoverage {
    # Registers a key so that it reports Ok when there was nothing to collect (e.g. no agent identities).
    param([Parameter(Mandatory)]$Coverage, [Parameter(Mandatory)][string[]]$Key)
    foreach ($k in $Key) {
        if (-not $Coverage.Contains($k)) {
            $Coverage[$k] = [ordered]@{
                Succeeded = 0
                Failed    = 0
                Statuses  = [ordered]@{}
                Messages  = [System.Collections.Generic.List[string]]::new()
            }
        }
    }
}

function Add-AgentIdCoverage {
    param(
        [Parameter(Mandatory)]$Coverage,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('Ok', 'Denied', 'NotSupported', 'Error', 'Skipped')][string]$Status,
        [string]$Message
    )
    Initialize-AgentIdCoverage -Coverage $Coverage -Key $Key
    $entry = $Coverage[$Key]
    if ($Status -eq 'Ok') {
        $entry.Succeeded++
        return
    }
    $entry.Failed++
    $entry.Statuses[$Status] = 1 + [int]$entry.Statuses[$Status]
    if ($Message -and $entry.Messages.Count -lt 3 -and -not $entry.Messages.Contains($Message)) {
        $entry.Messages.Add($Message)
    }
}

function Invoke-AgentIdStep {
    # Runs one collection call, records the outcome under $Key, and returns @{ Ok; Value } where Value is an
    # array (possibly empty) on success and $null on failure - $null meaning "unknown", never "none".
    param(
        [Parameter(Mandatory)]$Coverage,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        $value = @(& $ScriptBlock)
        Add-AgentIdCoverage -Coverage $Coverage -Key $Key -Status Ok
        return @{ Ok = $true; Value = $value }
    } catch {
        $info = Get-AgentIdErrorStatus $_
        Add-AgentIdCoverage -Coverage $Coverage -Key $Key -Status $info.AgentIdStatus -Message $info.Message
        return @{ Ok = $false; Value = $null }
    }
}

function Complete-AgentIdCoverage {
    param([Parameter(Mandatory)]$Coverage)
    $precedence = 'Denied', 'NotSupported', 'Error', 'Skipped'
    $result = [ordered]@{}
    foreach ($key in $Coverage.Keys) {
        $entry = $Coverage[$key]
        $status = if ($entry.Failed -eq 0) {
            'Ok'
        } elseif ($entry.Succeeded -eq 0) {
            $precedence | Where-Object { $entry.Statuses.Contains($_) } | Select-Object -First 1
        } else {
            'Partial'
        }
        $result[$key] = [ordered]@{
            Status    = $status
            Succeeded = $entry.Succeeded
            Failed    = $entry.Failed
            Detail    = ($entry.Messages -join ' | ')
        }
    }
    return $result
}
