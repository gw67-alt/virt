/**
 * WindowsVirtualizationEnabler.cpp
 *
 * A utility to enable virtualization features in Windows
 * using only core Windows API functions.
 */

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

// Function prototypes
BOOL IsProcessElevated();
BOOL CheckHardwareVirtualization();
BOOL EnableHyperV();
BOOL EnableVBS();
BOOL EnableCoreIsolation();
BOOL RunCommand(const wchar_t* command);
BOOL SetRegistryValue(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD data);
BOOL CheckFeatureStatus(const wchar_t* featureName);
void PrintStatus(const char* feature, BOOL status);
BOOL RestartSystem();

/**
 * Main function
 */
int main() {
    // Display banner
    printf("Windows Virtualization Enabler\n");
    printf("=============================\n\n");

    // Check if running with admin privileges
    if (!IsProcessElevated()) {
        printf("This program requires administrator privileges.\n");
        printf("Please right-click and select 'Run as administrator'.\n");
        return 1;
    }

    // Check hardware virtualization support
    printf("Checking hardware virtualization support...\n");
    BOOL hwVirtSupport = CheckHardwareVirtualization();
    PrintStatus("Hardware virtualization", hwVirtSupport);

    if (!hwVirtSupport) {
        printf("Hardware virtualization is not available or not enabled.\n");
        printf("Please enable virtualization in your BIOS/UEFI settings.\n");
        printf("Press any key to exit...\n");
        getchar();
        return 1;
    }

    // Feature statuses before changes
    printf("\nCurrent virtualization feature status:\n");
    printf("------------------------------------\n");
    PrintStatus("Hyper-V", CheckFeatureStatus(L"Microsoft-Hyper-V"));
    PrintStatus("Virtual Machine Platform", CheckFeatureStatus(L"VirtualMachinePlatform"));
    PrintStatus("Windows Hypervisor Platform", CheckFeatureStatus(L"HypervisorPlatform"));
    PrintStatus("Windows Sandbox", CheckFeatureStatus(L"Containers-DisposableClientVM"));

    // Enable Hyper-V
    printf("\nEnabling Hyper-V and related features...\n");
    BOOL hyperVEnabled = EnableHyperV();
    PrintStatus("Hyper-V initialization", hyperVEnabled);

    // Enable Virtualization Based Security
    printf("\nEnabling Virtualization Based Security (VBS)...\n");
    BOOL vbsEnabled = EnableVBS();
    PrintStatus("VBS initialization", vbsEnabled);

    // Enable Core Isolation (Memory Integrity)
    printf("\nEnabling Memory Integrity (Core Isolation)...\n");
    BOOL coreIsolationEnabled = EnableCoreIsolation();
    PrintStatus("Memory Integrity initialization", coreIsolationEnabled);

    // Summary and restart prompt
    printf("\nVirtualization configuration completed.\n");
    printf("A system restart is required for changes to take effect.\n\n");
    printf("Do you want to restart your computer now? (Y/N): ");

    char response;
    scanf(" %c", &response);

    if (response == 'Y' || response == 'y') {
        printf("Restarting system...\n");
        if (RestartSystem()) {
            printf("Restart initiated.\n");
        } else {
            printf("Failed to restart. Please restart manually.\n");
        }
    } else {
        printf("Please restart your computer manually to complete the setup.\n");
    }

    return 0;
}

/**
 * Check if the current process has administrator privileges
 */
BOOL IsProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }

        CloseHandle(hToken);
    }

    return isElevated;
}

/**
 * Check if hardware virtualization is supported and enabled
 */
BOOL CheckHardwareVirtualization() {
    int cpuInfo[4] = { 0 };

    // Check for virtualization feature flag
    __cpuid(cpuInfo, 1);
    BOOL vmxSupported = (cpuInfo[2] & (1 << 5)) != 0; // Check CPUID.1:ECX.VMX bit for Intel

    // For AMD, we would check SVM bit
    // AMD SVM check (simplified)
    __cpuid(cpuInfo, 0x80000001);
    BOOL svmSupported = (cpuInfo[2] & (1 << 2)) != 0; // Check CPUID.80000001H:ECX.SVM for AMD

    return vmxSupported || svmSupported;
}

/**
 * Enable Hyper-V and related Windows features
 */
BOOL EnableHyperV() {
    BOOL success = TRUE;

    // Enable main Hyper-V feature
    success &= RunCommand(L"dism /online /enable-feature /featurename:Microsoft-Hyper-V /all /norestart");

    // Enable additional virtualization features
    success &= RunCommand(L"dism /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart");
    success &= RunCommand(L"dism /online /enable-feature /featurename:HypervisorPlatform /all /norestart");

    // Windows Sandbox (optional)
    RunCommand(L"dism /online /enable-feature /featurename:Containers-DisposableClientVM /all /norestart");

    return success;
}

/**
 * Enable Virtualization Based Security
 */
BOOL EnableVBS() {
    BOOL success = TRUE;

    // Set registry values for VBS
    success &= SetRegistryValue(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                              L"EnableVirtualizationBasedSecurity",
                              1);

    success &= SetRegistryValue(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                              L"RequirePlatformSecurityFeatures",
                              1);

    success &= SetRegistryValue(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                              L"Enabled",
                              1);

    return success;
}

/**
 * Enable Core Isolation (Memory Integrity)
 */
BOOL EnableCoreIsolation() {
    BOOL success = TRUE;

    // Set registry values for Core Isolation/Memory Integrity
    success &= SetRegistryValue(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                              L"Enabled",
                              1);

    success &= SetRegistryValue(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                              L"HVCIMATRequired",
                              1);

    return success;
}

/**
 * Run a command using the Windows command processor
 */
BOOL RunCommand(const wchar_t* command) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    wchar_t cmdLine[4096] = { 0 };

    // Create command line with the command processor
    wcscpy(cmdLine, L"cmd.exe /c ");
    wcscat(cmdLine, command);

    // Create the process
    BOOL success = CreateProcessW(
        NULL,           // No module name (use command line)
        cmdLine,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        CREATE_NO_WINDOW, // Do not create a window
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi);           // Pointer to PROCESS_INFORMATION structure

    if (success) {
        // Wait for the process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Get the exit code
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (exitCode == 0);
    }

    return FALSE;
}

/**
 * Set a DWORD value in the registry
 */
BOOL SetRegistryValue(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD data) {
    HKEY hKey;
    DWORD disposition;
    LONG result = RegCreateKeyExW(
        hKeyRoot,
        subKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &disposition);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    result = RegSetValueExW(
        hKey,
        valueName,
        0,
        REG_DWORD,
        (BYTE*)&data,
        sizeof(DWORD));

    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

/**
 * Check if a Windows feature is enabled
 */
BOOL CheckFeatureStatus(const wchar_t* featureName) {
    wchar_t cmdLine[4096] = { 0 };
    wchar_t tempFileName[MAX_PATH] = { 0 };
    DWORD tempPathLen = GetTempPathW(MAX_PATH, tempFileName);

    if (tempPathLen == 0 || tempPathLen > MAX_PATH) {
        return FALSE;
    }

    // Create a temporary file name
    if (GetTempFileNameW(tempFileName, L"virt", 0, tempFileName) == 0) {
        return FALSE;
    }

    // Construct command to check feature status and redirect output
    swprintf(cmdLine, L"cmd.exe /c dism /online /get-featureinfo /featurename:%s > %s", featureName, tempFileName);

    // Execute command
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DeleteFileW(tempFileName);
        return FALSE;
    }

    // Wait for the process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Read the output file to check status
    HANDLE hFile = CreateFileW(tempFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(tempFileName);
        return FALSE;
    }

    // Read file content to check if feature is enabled
    char buffer[8192] = { 0 };
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        CloseHandle(hFile);
        DeleteFileW(tempFileName);
        return FALSE;
    }

    CloseHandle(hFile);
    DeleteFileW(tempFileName);

    // Check if output contains "State : Enabled"
    buffer[bytesRead] = 0;
    return (strstr(buffer, "State : Enabled") != NULL);
}

/**
 * Print status with consistent formatting
 */
void PrintStatus(const char* feature, BOOL status) {
    printf("%-40s: %s\n", feature, status ? "Enabled" : "Disabled");
}

/**
 * Restart the system
 */
BOOL RestartSystem() {
    // Use the explicit Unicode version of InitiateSystemShutdownEx
    // Note: We're using NULL for both lpMachineName and lpMessage
    return InitiateSystemShutdownExW(
        NULL,       // lpMachineName - NULL for local computer
        NULL,       // lpMessage - No message
        0,          // dwTimeout - Immediate shutdown
        TRUE,       // bForceAppsClosed - Force applications to close
        TRUE,       // bRebootAfterShutdown - Reboot after shutdown
        SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
        SHTDN_REASON_MINOR_RECONFIG |
        SHTDN_REASON_FLAG_PLANNED  // Shutdown reason code
    );
}
