$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $bytes = [Convert]::FromBase64String($request.data)
    $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    if ($request.operation -eq 'protect') {
        $result = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)
    } elseif ($request.operation -eq 'unprotect') {
        $result = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $scope)
    } else { throw 'Invalid operation' }
    [Console]::Out.Write([Convert]::ToBase64String($result))
} catch {
    [Console]::Error.WriteLine('Windows credential protection failed; existing keys were not replaced.')
    exit 1
}
