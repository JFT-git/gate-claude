# PowerShell normalizes C: paths through inaccessible AppContainer ancestors.
# A session-local drive starts at the already validated native working directory.
$guardNativeDirectory = [Environment]::CurrentDirectory
New-PSDrive -Name Guard -PSProvider FileSystem -Root $guardNativeDirectory -Scope Global -ErrorAction Stop | Out-Null
Set-Location -LiteralPath 'Guard:\' -ErrorAction Stop
Remove-Variable guardNativeDirectory

# The native CLI writes (Get-Location).Path to its next process's Win32 cwd.
# Keep the provider drive private, while exposing the physical FileSystem path.
function global:Get-Location {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(ParameterSetName = 'Path')][string[]] $PSProvider,
        [Parameter(ParameterSetName = 'Path')][string[]] $PSDrive,
        [Parameter(ParameterSetName = 'Stack')][switch] $Stack,
        [Parameter(ParameterSetName = 'Stack')][string[]] $StackName
    )
    if ($PSCmdlet.ParameterSetName -eq 'Stack') {
        Microsoft.PowerShell.Management\Get-Location @PSBoundParameters
        return
    }
    foreach ($location in Microsoft.PowerShell.Management\Get-Location @PSBoundParameters) {
        if ($location -is [System.Management.Automation.PathInfo] -and
            $location.Provider.Name -eq 'FileSystem') {
            Add-Member -InputObject $location -MemberType NoteProperty -Name Path -Value $location.ProviderPath -Force
        }
        $location
    }
}
