# generate_ascii_dir_repr.ps1
# Generates an ASCII tree representation of a directory structure
#
# Source - https://stackoverflow.com/a
# Posted by Podbrushkin, modified by community. See post 'Timeline' for change history
# Retrieved 2025-12-07, License - CC BY-SA 4.0

<#
.SYNOPSIS
    Builds an ASCII tree from a list of paths.

.DESCRIPTION
    Takes a list of file/directory paths and converts them into a nested hashtable
    structure, then renders it as an ASCII tree with box-drawing characters.
    This is a helper function used by Build-AsciiFileTree.

.PARAMETER Paths
    An array of path strings to be converted into a tree structure.
    Accepts pipeline input.

.PARAMETER Delimiter
    The character used to split path components (e.g., '\' on Windows, '/' on Unix).

.EXAMPLE
    @("src\main.py", "src\utils\helper.py", "docs\README.md") | Build-AsciiTree -Delimiter '\'

.OUTPUTS
    String[] - Lines of ASCII art representing the tree structure.
#>
function Build-AsciiTree {
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string[]]$Paths,

        [Parameter(Mandatory=$true)]
        [char]$Delimiter
    )

    begin {
        # Initialize empty hashtable to store the tree structure
        $tree = @{}
    }

    process {
        # Process each path and build nested hashtable structure
        foreach ($path in $Paths) {
            # Split path into components
            $parts = $path.Split($Delimiter)
            $current = $tree

            # Traverse/create nested structure for each path component
            foreach ($part in $parts) {
                if (-not $current.ContainsKey($part)) {
                    $current[$part] = @{}
                }
                $current = $current[$part]
            }
        }
    }

    end {
        <#
        .SYNOPSIS
            Recursively renders a branch of the tree as ASCII art.

        .PARAMETER node
            The current hashtable node to render.

        .PARAMETER prefix
            The string prefix for indentation and tree lines.
        #>
        function Build-Branch {
            param(
                [hashtable]$node,
                [string]$prefix = ""
            )

            # Sort keys alphabetically for consistent output
            $keys = $node.Keys | Sort-Object
            $count = $keys.Count
            $i = 0

            foreach ($key in $keys) {
                $i++
                $isLast = ($i -eq $count)

                # Use different box-drawing characters for last item vs others
                if ($isLast) {
                    Write-Output ("$prefix└── $key")
                    $newPrefix = "$prefix    "  # No vertical line for last item's children
                } else {
                    Write-Output ("$prefix├── $key")
                    $newPrefix = "$prefix│   "  # Continue vertical line for siblings
                }

                # Recursively render children
                Build-Branch -node $node[$key] -prefix $newPrefix
            }
        }

        # Start rendering from the root
        Build-Branch -node $tree
    }
}

<#
.SYNOPSIS
    Generates an ASCII tree representation of a directory structure.

.DESCRIPTION
    Scans a directory recursively and outputs an ASCII tree showing the
    file and folder hierarchy. Supports excluding files/folders by pattern
    and limiting recursion depth.

.PARAMETER Directory
    The root directory to scan. Defaults to current directory '.'.

.PARAMETER Depth
    Maximum recursion depth. Defaults to 2.

.PARAMETER Exclude
    Array of glob patterns to exclude (e.g., ".*" for hidden files, "__pycache__").
    Patterns are matched against both file/folder names and full paths.

.PARAMETER Absolute
    If specified, outputs absolute paths instead of relative paths.

.EXAMPLE
    Build-AsciiFileTree -Directory "C:\Projects\MyApp" -Depth 3

.EXAMPLE
    Build-AsciiFileTree -Directory . -Exclude @(".*", "__pycache__", "node_modules")

.EXAMPLE
    # Using the 'tree' alias
    tree . -Exclude ".*,__pycache__" -Depth 5

.OUTPUTS
    String[] - Lines of ASCII art representing the directory tree.
#>
function Build-AsciiFileTree {
    param (
        [Parameter(Position=0)]
        [string]$Directory = '.',

        [Parameter()]
        [int]$Depth = 2,

        [Parameter()]
        [string[]]$Exclude = @(),

        [switch]$Absolute
    )

    # Get the platform-specific path delimiter
    $Delimiter = [IO.Path]::DirectorySeparatorChar

    # Resolve to absolute path for consistent path manipulation
    $resolvedDir = Resolve-Path $Directory

    # Get all files and directories, applying exclusion filters
    $files = Get-ChildItem $Directory -Recurse -Depth $Depth -Force | Where-Object {
        $item = $_
        $excluded = $false

        # Check each exclusion pattern
        foreach ($pattern in $Exclude) {
            # Match against the item name directly
            if ($item.Name -like $pattern) {
                $excluded = $true
                break
            }
            # Match against full path (for nested exclusions)
            if ($item.FullName -like "*$Delimiter$pattern$Delimiter*" -or $item.FullName -like "*$Delimiter$pattern") {
                $excluded = $true
                break
            }
        }
        -not $excluded
    }

    # Output the root directory name as the tree header
    Write-Output (Split-Path $resolvedDir -Leaf)

    if ($Absolute) {
        # Output absolute paths
        $files | ForEach-Object { $_.FullName } | Build-AsciiTree -Delimiter $Delimiter
    } else {
        # Convert to relative paths and build tree
        $files |
            ForEach-Object {
                # Extract the relative portion of the path
                $relativePath = $_.FullName.Substring($resolvedDir.Path.Length).TrimStart($Delimiter)
                if ($relativePath) { $relativePath }
            } |
            Where-Object { $_ } |
            Build-AsciiTree -Delimiter $Delimiter
    }
}

# Create a convenient alias for the main function
Set-Alias -Name tree -Value Build-AsciiFileTree

# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================
# When script is executed directly with arguments, parse them and run the tree
#
# Usage:
#   .\generate_ascii_dir_repr.ps1 <directory> [-Exclude <patterns>] [-Depth <n>]
#
# Examples:
#   .\generate_ascii_dir_repr.ps1 .
#   .\generate_ascii_dir_repr.ps1 C:\Projects -Exclude ".*,__pycache__" -Depth 5
#   .\generate_ascii_dir_repr.ps1 . -Exclude ".git,.pixi,node_modules"
# =============================================================================
if ($args.Count -gt 0) {
    $dir = $args[0]
    $excludePatterns = @()
    $depth = 10  # Default to deep recursion when run from CLI

    # Parse command-line arguments
    for ($i = 1; $i -lt $args.Count; $i++) {
        if ($args[$i] -eq '-Exclude' -and $i + 1 -lt $args.Count) {
            # Split comma-separated patterns into array
            $excludePatterns = $args[$i + 1] -split ','
            $i++
        }
        elseif ($args[$i] -eq '-Depth' -and $i + 1 -lt $args.Count) {
            $depth = [int]$args[$i + 1]
            $i++
        }
    }

    # Execute the tree generation
    Build-AsciiFileTree -Directory $dir -Depth $depth -Exclude $excludePatterns
}
