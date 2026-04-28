# CONFIG
$projectPath = "$PSScriptRoot/src"
$outputFile  = "$PSScriptRoot/dump.txt"
$maxFileSizeKB = 200

# File types
$extensions = @(".py")

# Folders to exclude
$excludeDirs = @(".pycache")

# Clear output
if (Test-Path $outputFile) {
    Remove-Item $outputFile
}

# Get files safely
$files = Get-ChildItem -Path $projectPath -Recurse -File | Where-Object {
    $file = $_

    # Check extension
    if ($extensions -notcontains $file.Extension) {
        return $false
    }

    # Exclude directories safely
    foreach ($dir in $excludeDirs) {
        if ($file.FullName -like "*\$dir\*") {
            return $false
        }
    }

    return $true
}

foreach ($file in $files) {

    # Skip large files
    if ($file.Length -gt ($maxFileSizeKB * 1024)) {
        continue
    }

    # Header
    Add-Content $outputFile "`n========================================="
    Add-Content $outputFile "FILE: $($file.FullName)"
    Add-Content $outputFile "========================================="

    try {
        Get-Content $file.FullName -Raw | Add-Content $outputFile
    } catch {
        Add-Content $outputFile "[ERROR READING FILE]"
    }

    Add-Content $outputFile "`n"
}

Write-Host "Clean dump created at $outputFile"