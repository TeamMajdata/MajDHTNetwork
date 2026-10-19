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

$libraryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../CSharp/MajDHTNetwork')).ProviderPath
$packageDirectory = Join-Path $libraryRoot 'artifacts/nuget'
$dllDirectory = Join-Path $libraryRoot "artifacts/dll/$Version"
$package = Join-Path $packageDirectory "MajDHTNetwork.$Version.nupkg"
$archive = [System.IO.Compression.ZipFile]::OpenRead($package)
try {
    $names = @($archive.Entries.FullName)
    foreach ($required in @('lib/netstandard2.1/MajDHTNetwork.dll', 'lib/netstandard2.1/MajDHTNetwork.xml', 'README.md', 'PROTOCOL.md', 'LICENSE')) {
        if ($names -notcontains $required) {
            throw "The NuGet package is missing $required."
        }
    }
    if (@($names | Where-Object { $_ -match '(^|/)(Tests|src|obj|bin)/' -or $_ -match 'MajDHTNetwork.Tests' }).Count -ne 0) {
        throw 'Test sources or build directories leaked into the NuGet package.'
    }
}
finally {
    $archive.Dispose()
}

$assets = Get-Content -LiteralPath (Join-Path $libraryRoot 'obj/project.assets.json') -Raw | ConvertFrom-Json
$workRoot = Join-Path $PSScriptRoot ('.work/consumers-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $workRoot -Force
$packageCache = Join-Path $workRoot 'packages'
$feeds = @($packageDirectory) + @($assets.packageFolders.PSObject.Properties.Name)
$sourceEntries = for ($index = 0; $index -lt $feeds.Count; $index++) {
    '<add key="source' + $index + '" value="' + [System.Security.SecurityElement]::Escape($feeds[$index]) + '" />'
}
$config = '<configuration><packageSources><clear />' + ($sourceEntries -join '') + '</packageSources></configuration>'

foreach ($mode in @('NuGet', 'Dll')) {
    $consumerRoot = Join-Path $workRoot $mode
    $consumerSource = Join-Path $consumerRoot 'src'
    $null = New-Item -ItemType Directory -Path $consumerSource -Force
    if ($mode -eq 'NuGet') {
        $references = '<PackageReference Include="MajDHTNetwork" Version="' + $Version + '" />'
    }
    else {
        $references = (Get-ChildItem -LiteralPath $dllDirectory -Filter '*.dll' -File | ForEach-Object {
            '<Reference Include="' + [System.Security.SecurityElement]::Escape($_.BaseName) + '"><HintPath>' + [System.Security.SecurityElement]::Escape($_.FullName) + '</HintPath></Reference>'
        }) -join ''
    }
    $project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><LangVersion>9.0</LangVersion><Nullable>enable</Nullable><ImplicitUsings>disable</ImplicitUsings><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup><ItemGroup>' + $references + '</ItemGroup></Project>'
    Set-Content -LiteralPath (Join-Path $consumerRoot 'Consumer.csproj') -Value $project -Encoding utf8
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ConsumerSmoke/Program.cs') -Destination (Join-Path $consumerSource 'Program.cs')
    Set-Content -LiteralPath (Join-Path $consumerRoot 'NuGet.Config') -Value $config -Encoding utf8
    Push-Location -LiteralPath $consumerRoot
    try {
        Invoke-Dotnet -CommandArguments @('restore', 'Consumer.csproj', '--packages', $packageCache, '--configfile', 'NuGet.Config')
        Invoke-Dotnet -CommandArguments @('run', '--project', 'Consumer.csproj', '--configuration', 'Release', '--no-restore')
    }
    finally {
        Pop-Location
    }
    Write-Output "PASS $mode artifact consumer."
}
