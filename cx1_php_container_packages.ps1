<#
.SYNOPSIS
  Checkmarx One: for every project, find the latest scan and query the Containers
  "buffet" GraphQL API for packages whose name contains "php".

.PARAMETER BaseUrl       Checkmarx One URL, e.g. https://eu.ast.checkmarx.net  (or env CX1_URL)
.PARAMETER Tenant        Tenant (realm) name                                    (or env CX1_TENANT)
.PARAMETER ApiKey        Checkmarx One API key (refresh token)                  (or env CX1_API_KEY)
.PARAMETER ClientId      OAuth client ID                                        (or env CX1_CLIENT_ID)
.PARAMETER ClientSecret  OAuth client secret                                    (or env CX1_CLIENT_SECRET)
.PARAMETER IamUrl        Override IAM URL (default: derived from BaseUrl, ast. -> iam.)
.PARAMETER Package       Substring to match in package names (default: php)
.PARAMETER AnyScan       Use the latest scan even if the containers engine did not run
.PARAMETER Out           Output file prefix (default: php_container_packages)

.EXAMPLE
  .\cx1_php_container_packages.ps1 -BaseUrl https://ast.checkmarx.net -Tenant mytenant -ApiKey $env:KEY
.EXAMPLE
  .\cx1_php_container_packages.ps1 -BaseUrl https://eu.ast.checkmarx.net -Tenant mytenant -ClientId my-client -ClientSecret $env:SECRET

  If scripts are blocked: powershell -ExecutionPolicy Bypass -File .\cx1_php_container_packages.ps1 ...
#>
[CmdletBinding()]
param(
    [string]$BaseUrl      = $env:CX1_URL,
    [string]$Tenant       = $env:CX1_TENANT,
    [string]$ApiKey       = $env:CX1_API_KEY,
    [string]$ClientId     = $env:CX1_CLIENT_ID,
    [string]$ClientSecret = $env:CX1_CLIENT_SECRET,
    [string]$IamUrl       = $env:CX1_IAM_URL,
    [string]$Package      = "php",
    [switch]$AnyScan,
    [string]$Out          = "php_container_packages"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $BaseUrl -or -not $Tenant) { throw "-BaseUrl and -Tenant are required (or CX1_URL / CX1_TENANT)" }
if (-not $ApiKey -and -not ($ClientId -and $ClientSecret)) { throw "Provide -ApiKey or -ClientId + -ClientSecret" }

$BaseUrl = $BaseUrl.TrimEnd('/')
if (-not $IamUrl) {
    # https://eu.ast.checkmarx.net -> https://eu.iam.checkmarx.net
    $IamUrl = $BaseUrl -replace '^(https?://)([^./]+\.)?ast\.', '$1$2iam.'
}
$IamUrl = $IamUrl.TrimEnd('/')

# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
$script:Token = $null
$script:TokenExpiry = [DateTime]::MinValue

function Get-Cx1Token {
    $url = "$IamUrl/auth/realms/$Tenant/protocol/openid-connect/token"
    if ($ApiKey) {
        $body = @{ grant_type = "refresh_token"; client_id = "ast-app"; refresh_token = $ApiKey }
    } else {
        $body = @{ grant_type = "client_credentials"; client_id = $ClientId; client_secret = $ClientSecret }
    }
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url -Body $body -ContentType "application/x-www-form-urlencoded"
    } catch {
        throw "Auth failed at ${url}: $($_.Exception.Message)"
    }
    if (-not $resp.access_token) { throw "Auth failed at ${url}: no access_token in response" }
    $script:Token = $resp.access_token
    $ttl = if ($resp.expires_in) { [int]$resp.expires_in } else { 1800 }
    $script:TokenExpiry = (Get-Date).AddSeconds($ttl - 60)
}

function Invoke-Cx1 {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$ExtraHeaders = @{},
        $Body = $null
    )
    $url = "$BaseUrl$Path"
    for ($attempt = 0; $attempt -le 4; $attempt++) {
        if ((Get-Date) -ge $script:TokenExpiry) { Get-Cx1Token }
        $headers = @{
            Authorization = "Bearer $($script:Token)"
            Accept        = "application/json; version=1.0"
        } + $ExtraHeaders
        try {
            $params = @{ Method = $Method; Uri = $url; Headers = $headers }
            if ($null -ne $Body) { $params.Body = $Body; $params.ContentType = "application/json" }
            return Invoke-RestMethod @params
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401 -and $attempt -eq 0) { Get-Cx1Token; continue }
            if ($code -in 429,500,502,503,504 -and $attempt -lt 4) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt)); continue
            }
            throw "HTTP $code $Method $Path : $($_.Exception.Message)"
        }
    }
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
Get-Cx1Token
Write-Host "Authenticated to $BaseUrl (IAM: $IamUrl)"

# ---- all projects (paged) ------------------------------------------------- #
$projects = @()
$offset = 0; $limit = 100
while ($true) {
    $resp  = Invoke-Cx1 -Method Get -Path "/api/projects?offset=$offset&limit=$limit"
    $batch = @($resp.projects)
    $projects += $batch
    $total = if ($resp.filteredTotalCount) { $resp.filteredTotalCount } elseif ($resp.totalCount) { $resp.totalCount } else { 0 }
    $offset += $batch.Count
    if ($batch.Count -eq 0 -or $offset -ge $total) { break }
}
Write-Host "Found $($projects.Count) projects"

$gqlQuery = "query FindPhpPackages(`$scanId: String!) { packagesByScan(scanId: `$scanId, skip: 0, take: 1000, where: { packageName: { contains: `"$Package`" } }) { totalCount items { packageName packageVersion type distribution runtimeUsage vulnerabilitiesCount images { imageName imageTag } } } }"

$results  = New-Object System.Collections.Generic.List[object]
$packages = New-Object System.Collections.Generic.List[object]

$i = 0
foreach ($p in $projects) {
    $i++
    $projId = $p.id; $pname = [string]$p.name
    $row = [ordered]@{
        projectId = $projId; projectName = $pname; scanId = ""; scanDate = ""; engines = ""
        containersScanned = $false; packageCount = 0; error = ""
    }

    try {
        # ---- latest scan (prefer one that ran the containers engine) -------- #
        $scansResp = Invoke-Cx1 -Method Get -Path "/api/scans?project-id=$projId&limit=25&sort=-created_at"
        $completed = @($scansResp.scans | Where-Object { $_.status -in "Completed","Partial" })

        if ($completed.Count -eq 0) {
            $row.error = "no completed scans"
        } else {
            $enginesOf = {
                param($s)
                $e = @($s.engines)
                $e += @($s.statusDetails | Where-Object { $_.status -eq "Completed" } | ForEach-Object { $_.name })
                @($e | Where-Object { $_ } | Sort-Object -Unique)
            }
            $scan = $null
            if (-not $AnyScan) {
                $scan = $completed | Where-Object { (& $enginesOf $_) -contains "containers" } | Select-Object -First 1
            }
            if (-not $scan) { $scan = $completed[0] }
            $engines = & $enginesOf $scan

            $row.scanId   = $scan.id
            $row.scanDate = [string]$scan.createdAt
            $row.engines  = ($engines -join ",")
            $row.containersScanned = ($engines -contains "containers")

            # ---- containers GraphQL ------------------------------------------ #
            if ($row.containersScanned -or $AnyScan) {
                $payload = @{ query = $gqlQuery; variables = @{ scanId = $scan.id } } | ConvertTo-Json -Depth 5 -Compress
                $gql = Invoke-Cx1 -Method Post -Path "/api/containers/buffet/graphql-V2" `
                                  -ExtraHeaders @{ "Cx-Project-Id" = $projId } -Body $payload
                if ($gql.errors) {
                    $row.error = (($gql.errors | ForEach-Object { $_.message }) -join "; ")
                } else {
                    $data  = $gql.data.packagesByScan
                    $items = @($data.items)
                    $row.packageCount = if ($null -ne $data.totalCount) { [int]$data.totalCount } else { $items.Count }
                    foreach ($it in $items) {
                        $packages.Add([pscustomobject][ordered]@{
                            projectId            = $projId
                            projectName          = $pname
                            scanId               = $scan.id
                            packageName          = $it.packageName
                            packageVersion       = $it.packageVersion
                            type                 = $it.type
                            distribution         = $it.distribution
                            runtimeUsage         = $it.runtimeUsage
                            vulnerabilitiesCount = $it.vulnerabilitiesCount
                            images               = (@($it.images | ForEach-Object { "$($_.imageName):$($_.imageTag)" }) -join ";")
                        })
                    }
                }
            } else {
                $row.error = "latest scan has no containers results"
            }
        }
    } catch {
        $row.error = ($_.Exception.Message).Substring(0, [math]::Min(200, $_.Exception.Message.Length))
    }

    $results.Add([pscustomobject]$row)
    $status = if ($row.packageCount -gt 0) { "$($row.packageCount) $Package pkgs" }
              elseif ($row.error) { $row.error } else { "no $Package pkgs" }
    $sid = if ($row.scanId) { $row.scanId } else { "-" }
    Write-Host ("[{0}/{1}] {2,-50} scan={3,-36} {4}" -f $i, $projects.Count, $pname.Substring(0,[math]::Min(50,$pname.Length)), $sid, $status)
}

# ---- outputs -------------------------------------------------------------- #
$projCsv = "${Out}_projects.csv"; $pkgCsv = "${Out}_packages.csv"; $jsonOut = "${Out}.json"
$results  | Export-Csv -Path $projCsv -NoTypeInformation -Encoding UTF8
$packages | Export-Csv -Path $pkgCsv  -NoTypeInformation -Encoding UTF8
@{ projects = $results; packages = $packages } | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonOut -Encoding UTF8

$hits = @($results | Where-Object { $_.packageCount -gt 0 })
Write-Host ""
Write-Host "=== Summary ==="
Write-Host "Projects scanned:              $($results.Count)"
Write-Host "Projects with containers scan: $(@($results | Where-Object { $_.containersScanned }).Count)"
Write-Host "Projects with '$Package' packages: $($hits.Count)"
foreach ($h in $hits) { Write-Host "  - $($h.projectName) ($($h.packageCount) packages, scan $($h.scanId))" }
Write-Host ""
Write-Host "Written: $projCsv, $pkgCsv, $jsonOut"
