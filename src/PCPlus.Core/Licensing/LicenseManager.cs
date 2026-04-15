using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PCPlus.Core.Interfaces;
using PCPlus.Core.Models;

namespace PCPlus.Core.Licensing
{
    /// <summary>
    /// License manager with device binding, server validation, and tamper detection.
    /// Device ID = hash of (motherboard serial + CPU ID + disk serial).
    /// License validated against server periodically.
    /// </summary>
    public class LicenseManager
    {
        private readonly string _configDir;
        private readonly string _licenseFile;
        private LicenseInfo _currentLicense;
        private readonly HttpClient _http;
        private string? _serverUrl;

        public LicenseInfo CurrentLicense => _currentLicense;

        public LicenseManager()
        {
            _configDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "PCPlusEndpoint");
            _licenseFile = Path.Combine(_configDir, "license.dat");
            _currentLicense = new LicenseInfo { Tier = LicenseTier.Free, IsValid = true };
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        }

        /// <summary>Generate a unique device ID from hardware identifiers.</summary>
        public static string GenerateDeviceId()
        {
            var components = new StringBuilder();

            // Motherboard serial
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT SerialNumber FROM Win32_BaseBoard");
                foreach (ManagementObject obj in searcher.Get())
                {
                    components.Append(obj["SerialNumber"]?.ToString() ?? "");
                    break;
                }
            }
            catch { components.Append("MB_UNKNOWN"); }

            components.Append("|");

            // CPU ID
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT ProcessorId FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    components.Append(obj["ProcessorId"]?.ToString() ?? "");
                    break;
                }
            }
            catch { components.Append("CPU_UNKNOWN"); }

            components.Append("|");

            // System drive serial
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT SerialNumber FROM Win32_DiskDrive WHERE Index=0");
                foreach (ManagementObject obj in searcher.Get())
                {
                    components.Append(obj["SerialNumber"]?.ToString()?.Trim() ?? "");
                    break;
                }
            }
            catch { components.Append("DISK_UNKNOWN"); }

            // SHA256 hash to create consistent device ID
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(components.ToString()));
            return Convert.ToHexString(hash)[..32]; // 32 char hex string
        }

        /// <summary>Load saved license from disk.</summary>
        public LicenseInfo LoadLicense()
        {
            try
            {
                if (File.Exists(_licenseFile))
                {
                    var encrypted = File.ReadAllBytes(_licenseFile);
                    var json = Unprotect(encrypted);
                    var license = JsonSerializer.Deserialize<LicenseInfo>(json);
                    if (license != null)
                    {
                        // Verify device binding
                        var currentDeviceId = GenerateDeviceId();
                        if (license.DeviceId == currentDeviceId)
                        {
                            _currentLicense = license;
                            return license;
                        }
                        else
                        {
                            // Device mismatch - license was copied from another machine
                            _currentLicense = new LicenseInfo
                            {
                                IsValid = false,
                                Tier = LicenseTier.Free,
                                StatusMessage = "License not valid for this device"
                            };
                        }
                    }
                }
            }
            catch
            {
                // Corrupted license file - tampered
                _currentLicense = new LicenseInfo
                {
                    IsValid = false,
                    Tier = LicenseTier.Free,
                    StatusMessage = "License file corrupted or tampered"
                };
            }

            return _currentLicense;
        }

        /// <summary>Activate a license key against the server.</summary>
        public async Task<LicenseInfo> ActivateAsync(string licenseKey, string serverUrl)
        {
            _serverUrl = serverUrl;
            var deviceId = GenerateDeviceId();

            try
            {
                var payload = new
                {
                    licenseKey,
                    deviceId,
                    hostname = Environment.MachineName,
                    username = Environment.UserName,
                    osVersion = Environment.OSVersion.ToString()
                };

                var json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _http.PostAsync($"{serverUrl}/api/license/activate", content);
                var body = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    var result = JsonSerializer.Deserialize<LicenseActivationResult>(body);
                    if (result != null && result.Success)
                    {
                        _currentLicense = new LicenseInfo
                        {
                            IsValid = true,
                            Tier = ParseTier(result.Tier),
                            CustomerId = result.CustomerId ?? "",
                            DeviceId = deviceId,
                            ExpiresAt = result.ExpiresAt,
                            LastValidated = DateTime.UtcNow,
                            EnabledFeatures = result.Features ?? Array.Empty<string>(),
                            StatusMessage = "Active"
                        };

                        SaveLicense(_currentLicense);
                        return _currentLicense;
                    }
                }

                return new LicenseInfo
                {
                    IsValid = false,
                    Tier = LicenseTier.Free,
                    StatusMessage = $"Activation failed: {body}"
                };
            }
            catch (Exception ex)
            {
                return new LicenseInfo
                {
                    IsValid = false,
                    Tier = LicenseTier.Free,
                    StatusMessage = $"Server error: {ex.Message}"
                };
            }
        }

        /// <summary>Validate license with server (periodic check).</summary>
        public async Task<bool> ValidateAsync()
        {
            if (string.IsNullOrEmpty(_serverUrl) || string.IsNullOrEmpty(_currentLicense.CustomerId))
                return _currentLicense.IsValid;

            try
            {
                var deviceId = GenerateDeviceId();
                var response = await _http.GetAsync(
                    $"{_serverUrl}/api/license/validate?customerId={_currentLicense.CustomerId}&deviceId={deviceId}");

                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    var result = JsonSerializer.Deserialize<LicenseValidationResult>(body);

                    if (result != null)
                    {
                        _currentLicense.IsValid = result.Valid;
                        _currentLicense.Tier = ParseTier(result.Tier);
                        _currentLicense.ExpiresAt = result.ExpiresAt;
                        _currentLicense.LastValidated = DateTime.UtcNow;
                        _currentLicense.StatusMessage = result.Valid ? "Active" : (result.Message ?? "Invalid");

                        SaveLicense(_currentLicense);
                        return result.Valid;
                    }
                }

                // Server unreachable - grace period (allow if validated within 7 days)
                if ((DateTime.UtcNow - _currentLicense.LastValidated).TotalDays < 7)
                    return _currentLicense.IsValid;

                _currentLicense.IsValid = false;
                _currentLicense.StatusMessage = "Unable to validate - grace period expired";
                return false;
            }
            catch
            {
                // Network error - grace period
                if ((DateTime.UtcNow - _currentLicense.LastValidated).TotalDays < 7)
                    return _currentLicense.IsValid;

                return false;
            }
        }

        private void SaveLicense(LicenseInfo license)
        {
            try
            {
                Directory.CreateDirectory(_configDir);
                var json = JsonSerializer.Serialize(license);
                var encrypted = Protect(json);
                File.WriteAllBytes(_licenseFile, encrypted);
            }
            catch { }
        }

        // DPAPI encryption - encrypted data is bound to this machine
        private static byte[] Protect(string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            return ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine);
        }

        private static string Unprotect(byte[] data)
        {
            var bytes = ProtectedData.Unprotect(data, null, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(bytes);
        }

        private static LicenseTier ParseTier(string? tier) => tier?.ToLower() switch
        {
            "standard" => LicenseTier.Standard,
            "premium" => LicenseTier.Premium,
            _ => LicenseTier.Free
        };

        private class LicenseActivationResult
        {
            public bool Success { get; set; }
            public string? Tier { get; set; }
            public string? CustomerId { get; set; }
            public DateTime ExpiresAt { get; set; }
            public string[]? Features { get; set; }
        }

        private class LicenseValidationResult
        {
            public bool Valid { get; set; }
            public string? Tier { get; set; }
            public DateTime ExpiresAt { get; set; }
            public string? Message { get; set; }
        }
    }
}
