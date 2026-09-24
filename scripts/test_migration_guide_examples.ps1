$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$guide = Get-Content -LiteralPath (Join-Path $repo 'MIGRATION_GUIDE.md') -Raw
$registry = Get-Content -LiteralPath (Join-Path $repo 'contracts/contracts/harpocrates-registry/src/lib.rs') -Raw
$global:MigrationCalls = @()
$global:MigrationDependencyFailure = $false

# Every executable example runs with these local stubs. No external process,
# network request, contract mutation, or real key is used by this test.
function stellar {
  $global:MigrationCalls += ,([string[]]$args)
  if ($global:MigrationDependencyFailure) { throw 'Simulated Stellar CLI failure.' }
}
function cargo { $global:MigrationCalls += ,([string[]](@('cargo') + $args)) }

function Assert-That([bool] $condition, [string] $message) {
  if (-not $condition) { throw $message }
}

function Assert-Syntax([string] $source, [string] $label) {
  $tokens = $null
  $errors = $null
  [System.Management.Automation.Language.Parser]::ParseInput($source, [ref] $tokens, [ref] $errors) | Out-Null
  Assert-That ($errors.Count -eq 0) "$label has PowerShell syntax errors: $($errors -join '; ')"
}

function Assert-ScriptReferences([string] $markdown) {
  foreach ($match in [regex]::Matches($markdown, '\.\\(?:contracts\\)?scripts\\[A-Za-z0-9-]+\.ps1')) {
    $relative = $match.Value -replace '^\.\\', ''
    Assert-That (Test-Path -LiteralPath (Join-Path $repo $relative) -PathType Leaf) "Missing guide script: $relative"
  }
}

function Assert-Call([string] $id, [string[]] $expected) {
  Assert-That ($global:MigrationCalls.Count -eq 1) "$id expected one mocked command, got $($global:MigrationCalls.Count)"
  $actual = [string[]] $global:MigrationCalls[0]
  Assert-That (($actual -join '|') -ceq ($expected -join '|')) "$id argument shape changed: $($actual -join ' ')"
}

function Run-Example([string] $id, [string] $source, [string] $scopeDecimal = '1') {
  $global:MigrationCalls = @()
  $Admin = 'fixture-admin'
  $RegistryContractId = 'fixture-registry'
  $VerifierContractId = 'fixture-new-verifier'
  $OldVerifierContractId = 'fixture-old-verifier'
  $VerifierWasm = 'fixture-verifier.wasm'
  $VerifierVk = 'fixture-vk'
  $ScopeFieldDecimal = $scopeDecimal
  $ScopeHex = '0' * 63 + '1'
  $PreviousEpoch = 2
  Push-Location $repo
  try { & ([scriptblock]::Create($source)) }
  finally { Pop-Location }
}

Assert-ScriptReferences $guide
Assert-That ($registry.Contains('pub fn set_verifier(')) 'Contract no longer exposes set_verifier.'
Assert-That ($registry.Contains('pub fn set_scope_epoch(')) 'Contract no longer exposes set_scope_epoch.'
Assert-That (Test-Path -LiteralPath (Join-Path $repo 'frontend/src/seedVault.ts')) 'Canonical scope derivation is missing.'

$allFences = [regex]::Matches($guide, '(?ms)^\s*```powershell\s*\r?\n(.*?)\r?\n\s*```')
Assert-That ($allFences.Count -ge 5) 'Expected PowerShell examples are missing.'
foreach ($fence in $allFences) { Assert-Syntax $fence.Groups[1].Value 'Migration guide example' }

$marked = [regex]::Matches($guide, '(?ms)<!-- ci-example: ([a-z-]+) -->\s*```powershell\s*\r?\n(.*?)\r?\n\s*```')
$examples = @{}
foreach ($match in $marked) {
  $id = $match.Groups[1].Value
  Assert-That (-not $examples.ContainsKey($id)) "Duplicate CI example: $id"
  $examples[$id] = $match.Groups[2].Value
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($examples[$id], [ref] $tokens, [ref] $errors)
  foreach ($command in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $name = $command.GetCommandName()
    Assert-That ($name -cin @('stellar', 'cargo', 'cd', '.\contracts\scripts\set-verifier.ps1')) "Unmocked command in $id`: $name"
  }
}

$expectedIds = @('deploy-verifier', 'attach-verifier', 'set-scope-epoch', 'contract-tests', 'rollback-verifier', 'rollback-epoch')
Assert-That ($examples.Count -eq $expectedIds.Count) 'CI example count changed.'
foreach ($id in $expectedIds) { Assert-That ($examples.ContainsKey($id)) "CI example missing: $id" }
foreach ($id in @('deploy-verifier', 'set-scope-epoch', 'rollback-epoch')) {
  Assert-That ($examples[$id] -match '(?m)^\s*--\s*') "$id lost its Stellar CLI argument separator."
}

Run-Example 'deploy-verifier' $examples['deploy-verifier']
Assert-Call 'deploy-verifier' @('contract', 'deploy', '--wasm', 'fixture-verifier.wasm', '--source', 'fixture-admin', '--network', 'testnet', '--vk_bytes-file-path', 'fixture-vk')
Run-Example 'attach-verifier' $examples['attach-verifier']
Assert-Call 'attach-verifier' @('contract', 'invoke', '--id', 'fixture-registry', '--source', 'fixture-admin', '--network', 'testnet', 'set_verifier', '--admin', 'fixture-admin', '--verifier', 'fixture-new-verifier')
Run-Example 'set-scope-epoch' $examples['set-scope-epoch']
Assert-Call 'set-scope-epoch' @('contract', 'invoke', '--id', 'fixture-registry', '--source', 'fixture-admin', '--network', 'testnet', 'set_scope_epoch', '--admin', 'fixture-admin', '--scope', ('0' * 63 + '1'), '--epoch', '0')
Run-Example 'contract-tests' $examples['contract-tests']
Assert-Call 'contract-tests' @('cargo', 'test', '--lib')
Run-Example 'rollback-verifier' $examples['rollback-verifier']
Assert-Call 'rollback-verifier' @('contract', 'invoke', '--id', 'fixture-registry', '--source', 'fixture-admin', '--network', 'testnet', 'set_verifier', '--admin', 'fixture-admin', '--verifier', 'fixture-old-verifier')
Run-Example 'rollback-epoch' $examples['rollback-epoch']
Assert-Call 'rollback-epoch' @('contract', 'invoke', '--id', 'fixture-registry', '--source', 'fixture-admin', '--network', 'testnet', 'set_scope_epoch', '--admin', 'fixture-admin', '--scope', ('0' * 63 + '1'), '--epoch', '2')

Run-Example 'largest valid scope' $examples['set-scope-epoch'] '21888242871839275222246405745257275088548364400416034343698204186575808495616'
Assert-Call 'largest valid scope' @('contract', 'invoke', '--id', 'fixture-registry', '--source', 'fixture-admin', '--network', 'testnet', 'set_scope_epoch', '--admin', 'fixture-admin', '--scope', '30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000000', '--epoch', '0')

$global:MigrationDependencyFailure = $true
$dependencyFailed = $false
try { Run-Example 'dependency-failure' $examples['deploy-verifier'] }
catch { $dependencyFailed = ($_.Exception.Message -eq 'Simulated Stellar CLI failure.') }
finally { $global:MigrationDependencyFailure = $false }
Assert-That ($dependencyFailed -and $global:MigrationCalls.Count -eq 1) 'Stellar CLI failure was not propagated safely.'

# Negative and boundary inputs must fail before any mocked contract invocation.
foreach ($invalid in @('0', 'not-a-number', '21888242871839275222246405745257275088548364400416034343698204186575808495617')) {
  $ScopeFieldDecimal = $invalid
  $global:MigrationCalls = @()
  $failed = $false
  try { & ([scriptblock]::Create($examples['set-scope-epoch'])) } catch { $failed = $true }
  Assert-That ($failed -and $global:MigrationCalls.Count -eq 0) "Invalid scope reached stellar: $invalid"
}
foreach ($invalid in @(('0' * 63), ('0' * 65), ('z' * 64))) {
  $ScopeHex = $invalid
  $global:MigrationCalls = @()
  $failed = $false
  try { & ([scriptblock]::Create($examples['rollback-epoch'])) } catch { $failed = $true }
  Assert-That ($failed -and $global:MigrationCalls.Count -eq 0) 'Malformed rollback scope reached stellar.'
}
foreach ($invalid in @('-1', '18446744073709551616', 'not-an-epoch')) {
  $ScopeHex = '0' * 63 + '1'
  $PreviousEpoch = $invalid
  $global:MigrationCalls = @()
  $failed = $false
  try { & ([scriptblock]::Create($examples['rollback-epoch'])) } catch { $failed = $true }
  Assert-That ($failed -and $global:MigrationCalls.Count -eq 0) 'Invalid rollback epoch reached stellar.'
}

$badReference = $guide.Replace('.\contracts\scripts\set-verifier.ps1', '.\contracts\scripts\missing-verifier.ps1')
$missingRejected = $false
try { Assert-ScriptReferences $badReference } catch { $missingRejected = $true }
Assert-That $missingRejected 'Missing script regression was not detected.'
$syntaxRejected = $false
try { Assert-Syntax 'stellar contract invoke `' 'broken continuation' } catch { $syntaxRejected = $true }
Assert-That $syntaxRejected 'Malformed PowerShell regression was not detected.'

Write-Output "MIGRATION_GUIDE_EXAMPLES = PASS ($($examples.Count) executable fixtures; syntax, arguments, negative, boundary, and dependency-failure cases)"
