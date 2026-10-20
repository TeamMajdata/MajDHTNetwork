[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string]$Version = '0.1.0'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Dotnet {
    param([string[]]$CommandArguments)
    & dotnet @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($CommandArguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

$testRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../Tests/MajDHTNetwork.Tests')).ProviderPath
$testProject = Join-Path $testRoot 'MajDHTNetwork.Tests.csproj'

Push-Location -LiteralPath $PSScriptRoot
try {
    Invoke-Dotnet -CommandArguments @('restore', 'MajDHTNetwork.csproj', '--locked-mode')
    Invoke-Dotnet -CommandArguments @('build', 'MajDHTNetwork.csproj', '--configuration', 'Release', '--no-restore', "-p:Version=$Version")
    Invoke-Dotnet -CommandArguments @('restore', $testProject, '--locked-mode')
    Invoke-Dotnet -CommandArguments @('test', $testProject, '--configuration', 'Release', '--no-restore', "-p:Version=$Version")
    Invoke-Dotnet -CommandArguments @('pack', 'MajDHTNetwork.csproj', '--configuration', 'Release', '--no-build', '--no-restore', "-p:Version=$Version")

    $distributionDirectory = Join-Path $PSScriptRoot "artifacts/dll/$Version"
    $licenseDirectory = Join-Path $distributionDirectory 'licenses'
    $null = New-Item -ItemType Directory -Path $licenseDirectory -Force
    $outputDirectory = Join-Path $PSScriptRoot 'bin/Release/netstandard2.1'
    $distributionFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($pattern in @('*.dll', '*.xml', 'MajDHTNetwork.pdb')) {
        foreach ($file in Get-ChildItem -LiteralPath $outputDirectory -Filter $pattern -File) {
            $destination = Join-Path $distributionDirectory $file.Name
            Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
            $distributionFiles.Add($destination)
        }
    }
    foreach ($document in @('README.md', 'PROTOCOL.md', 'IMPLEMENTING.md')) {
        $destination = Join-Path $distributionDirectory $document
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $document) -Destination $destination -Force
        $distributionFiles.Add($destination)
    }
    $license = Join-Path $distributionDirectory 'LICENSE'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../../../LICENSE') -Destination $license -Force
    $distributionFiles.Add($license)

    # Preserve dependency license notices when redistributing loose DLLs.
    $assets = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'obj/project.assets.json') -Raw | ConvertFrom-Json
    foreach ($library in $assets.libraries.PSObject.Properties) {
        if ($library.Value.type -ne 'package') {
            continue
        }
        foreach ($folder in $assets.packageFolders.PSObject.Properties.Name) {
            $packageDirectory = Join-Path $folder $library.Value.path
            if (-not (Test-Path -LiteralPath $packageDirectory -PathType Container)) {
                continue
            }
            foreach ($notice in Get-ChildItem -LiteralPath $packageDirectory -File) {
                if ($notice.Name -notmatch '^(LICENSE|LICENCE|THIRD.PARTY.NOTICES)') {
                    continue
                }
                $noticeName = $library.Name.Replace('/', '.') + '.' + $notice.Name
                Copy-Item -LiteralPath $notice.FullName -Destination (Join-Path $licenseDirectory $noticeName) -Force
            }
            break
        }
    }
    $distributionFiles.Add($licenseDirectory)
    $archive = Join-Path $PSScriptRoot "artifacts/MajDHTNetwork.$Version.dll.zip"
    Compress-Archive -LiteralPath $distributionFiles.ToArray() -DestinationPath $archive -Force

    & (Join-Path $testRoot 'ValidatePackage.ps1') -Version $Version
    Write-Output "NuGet package: $(Join-Path $PSScriptRoot "artifacts/nuget/MajDHTNetwork.$Version.nupkg")"
    Write-Output "Symbols: $(Join-Path $PSScriptRoot "artifacts/nuget/MajDHTNetwork.$Version.snupkg")"
    Write-Output "DLL distribution: $archive"
}
finally {
    Pop-Location
}
