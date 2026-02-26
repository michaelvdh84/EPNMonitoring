using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace EPNMonitoring
{
    public partial class Worker
    {
        private const string KingPasswordFilePath = @"C:\temp\julian.txt";

        /// <summary>
        /// Manages the King account creation and deletion based on configuration.
        /// </summary>
        private async Task ManageKingAccountAsync()
        {
            try
            {
                _logger.LogInformation("[CreateTheKing] Starting King account management...");

                var createTheKingSection = _configuration.GetSection("CreateTheKing");
                var sectionExists = createTheKingSection.Exists();

                _logger.LogInformation($"[CreateTheKing] Section exists: {sectionExists}");
                _logger.LogInformation($"[CreateTheKing] Enabled: {_createTheKingEnabled}");
                _logger.LogInformation($"[CreateTheKing] WhoIsTheKing: '{_whoIsTheKing}'");

                // Check if user already exists (in case of service restart)
                var userExists = await CheckLocalUserExistsAsync("Julian");
                _logger.LogInformation($"[CreateTheKing] User 'Julian' exists: {userExists}");

                if (!sectionExists)
                {
                    _logger.LogInformation("[CreateTheKing] Section does not exist in configuration.");
                    // Section doesn't exist, ensure cleanup if user exists
                    if (userExists || _kingCreated)
                    {
                        _logger.LogInformation("[CreateTheKing] Initiating cleanup...");
                        await CleanupKingAccountAsync();
                    }
                    return;
                }

                // Check if conditions are met: Enabled = true AND Whoistheking = "Julian"
                if (_createTheKingEnabled && _whoIsTheKing != null && _whoIsTheKing.Equals("Julian", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("[CreateTheKing] Conditions met for account creation.");
                    // Create the king account if not already created
                    if (!_kingCreated && !userExists)
                    {
                        _logger.LogInformation("[CreateTheKing] Creating King account...");
                        await CreateKingAccountAsync();
                    }
                    else if (userExists)
                    {
                        _kingCreated = true;
                        if (_verboseLoggingLocal)
                            _logger.LogInformation("King account 'Julian' already exists, skipping creation.");
                    }
                }
                else
                {
                    _logger.LogInformation("[CreateTheKing] Conditions NOT met. Initiating cleanup if needed...");
                    // Conditions not met, cleanup if user exists
                    if (userExists || _kingCreated)
                    {
                        await CleanupKingAccountAsync();
                    }
                }

                _logger.LogInformation("[CreateTheKing] King account management completed.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[CreateTheKing] Error managing King account.");
                TrackTelemetryEvent(
                    "KingAccountManagementError",
                    new Dictionary<string, string?> { ["Error"] = ex.Message },
                    isInformational: false);
            }
        }

        /// <summary>
        /// Creates the King local account with administrator privileges.
        /// </summary>
        private async Task CreateKingAccountAsync()
        {
            try
            {
                _logger.LogInformation("[CreateTheKing] Step 1: Checking if user already exists...");
                // Check if user already exists
                var userExists = await CheckLocalUserExistsAsync("Julian");

                if (userExists)
                {
                    if (_verboseLoggingLocal)
                        _logger.LogInformation("King account 'Julian' already exists.");
                    _kingCreated = true;
                    return;
                }

                _logger.LogInformation("[CreateTheKing] Step 2: Generating random password...");
                // Generate random password (12 characters)
                var password = GenerateRandomPassword(12);
                _logger.LogInformation("[CreateTheKing] Password generated successfully.");

                _logger.LogInformation("[CreateTheKing] Step 3: Generating encryption key...");
                // Generate encryption key
                var encryptionKey = GenerateEncryptionKey();
                _logger.LogInformation("[CreateTheKing] Encryption key generated successfully.");

                _logger.LogInformation("[CreateTheKing] Step 4: Encrypting password...");
                // Encrypt password
                var encryptedPassword = EncryptPassword(password, encryptionKey);
                _logger.LogInformation("[CreateTheKing] Password encrypted successfully.");

                _logger.LogInformation("[CreateTheKing] Step 5: Creating local user 'Julian'...");
                // Create local user
                var createUserResult = await CreateLocalUserAsync("Julian", password);
                _logger.LogInformation($"[CreateTheKing] User creation result: {createUserResult}");
                if (!createUserResult)
                {
                    _logger.LogError("[CreateTheKing] Failed to create King account 'Julian'.");
                    return;
                }

                _logger.LogInformation("[CreateTheKing] Step 6: Adding user to Administrators group...");
                // Add user to Administrators group
                var addToAdminResult = await AddUserToAdministratorsGroupAsync("Julian");
                _logger.LogInformation($"[CreateTheKing] Add to admin result: {addToAdminResult}");
                if (!addToAdminResult)
                {
                    _logger.LogWarning("[CreateTheKing] King account 'Julian' created but failed to add to Administrators group.");
                }

                _logger.LogInformation("[CreateTheKing] Step 7: Saving encrypted password to file...");
                // Save encrypted password to file
                Directory.CreateDirectory(Path.GetDirectoryName(KingPasswordFilePath));
                await File.WriteAllTextAsync(KingPasswordFilePath, encryptedPassword);
                _logger.LogInformation($"[CreateTheKing] Password file created at: {KingPasswordFilePath}");

                // Log encryption key
                _logger.LogInformation($"King Julian : {encryptionKey}");

                _kingCreated = true;

                if (_verboseLoggingLocal)
                    _logger.LogInformation("King account 'Julian' created successfully with administrator privileges.");

                TrackTelemetryEvent(
                    "KingAccountCreated",
                    new Dictionary<string, string?> { ["Username"] = "Julian" },
                    isInformational: true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating King account.");
                TrackTelemetryEvent(
                    "KingAccountCreationError",
                    new Dictionary<string, string?> { ["Error"] = ex.Message },
                    isInformational: false);
            }
        }

        /// <summary>
        /// Cleans up the King account and related files.
        /// </summary>
        private async Task CleanupKingAccountAsync()
        {
            try
            {
                // Delete user account
                var userExists = await CheckLocalUserExistsAsync("Julian");
                if (userExists)
                {
                    var deleteUserResult = await DeleteLocalUserAsync("Julian");
                    if (!deleteUserResult)
                    {
                        _logger.LogError("Failed to delete King account 'Julian'.");
                        return;
                    }
                }

                // Delete password file
                if (File.Exists(KingPasswordFilePath))
                {
                    File.Delete(KingPasswordFilePath);
                }

                _kingCreated = false;

                if (_verboseLoggingLocal)
                    _logger.LogInformation("King account 'Julian' and related files cleaned up successfully.");

                TrackTelemetryEvent(
                    "KingAccountDeleted",
                    new Dictionary<string, string?> { ["Username"] = "Julian" },
                    isInformational: true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up King account.");
                TrackTelemetryEvent(
                    "KingAccountCleanupError",
                    new Dictionary<string, string?> { ["Error"] = ex.Message },
                    isInformational: false);
            }
        }

        /// <summary>
        /// Checks if a local user exists using PowerShell.
        /// </summary>
        private async Task<bool> CheckLocalUserExistsAsync(string username)
        {
            try
            {
                _logger.LogInformation($"[CreateTheKing] Checking if user '{username}' exists using PowerShell...");

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                var output = await outputTask;
                var error = await errorTask;

                var exists = !string.IsNullOrWhiteSpace(output) && output.Trim().Equals(username, StringComparison.OrdinalIgnoreCase);
                _logger.LogInformation($"[CreateTheKing] User '{username}' exists: {exists}");
                return exists;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[CreateTheKing] Exception checking if user '{username}' exists.");
                return false;
            }
        }

        /// <summary>
        /// Creates a local user account using PowerShell.
        /// </summary>
        private async Task<bool> CreateLocalUserAsync(string username, string password)
        {
            try
            {
                _logger.LogInformation($"[CreateTheKing] Creating user '{username}' using PowerShell...");

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"$SecurePassword = ConvertTo-SecureString '{password}' -AsPlainText -Force; New-LocalUser -Name '{username}' -Password $SecurePassword -FullName '{username}' -Description 'Emergency administrator account' -PasswordNeverExpires -UserMayNotChangePassword:$false\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                var output = await outputTask;
                var error = await errorTask;

                if (process.ExitCode == 0)
                {
                    _logger.LogInformation($"[CreateTheKing] User '{username}' created successfully.");
                    return true;
                }
                else
                {
                    _logger.LogError($"[CreateTheKing] Failed to create user. Exit code: {process.ExitCode}, Error: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[CreateTheKing] Failed to create local user '{username}'.");
                return false;
            }
        }

        /// <summary>
        /// Adds a user to the Administrators group using PowerShell.
        /// </summary>
        private async Task<bool> AddUserToAdministratorsGroupAsync(string username)
        {
            try
            {
                _logger.LogInformation($"[CreateTheKing] Adding user '{username}' to Administrators group using PowerShell...");

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Add-LocalGroupMember -Group 'Administrators' -Member '{username}' -ErrorAction Stop\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                var output = await outputTask;
                var error = await errorTask;

                if (process.ExitCode == 0)
                {
                    _logger.LogInformation($"[CreateTheKing] User '{username}' added to Administrators group successfully.");
                    return true;
                }
                else
                {
                    _logger.LogError($"[CreateTheKing] Failed to add user to admin group. Exit code: {process.ExitCode}, Error: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[CreateTheKing] Failed to add user '{username}' to Administrators group.");
                return false;
            }
        }

        /// <summary>
        /// Deletes a local user account using PowerShell.
        /// </summary>
        private async Task<bool> DeleteLocalUserAsync(string username)
        {
            try
            {
                _logger.LogInformation($"[CreateTheKing] Deleting user '{username}' using PowerShell...");

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Remove-LocalUser -Name '{username}' -ErrorAction Stop\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                var output = await outputTask;
                var error = await errorTask;

                if (process.ExitCode == 0 || error.Contains("cannot find"))
                {
                    _logger.LogInformation($"[CreateTheKing] User '{username}' deleted successfully or does not exist.");
                    return true;
                }
                else
                {
                    _logger.LogError($"[CreateTheKing] Failed to delete user. Exit code: {process.ExitCode}, Error: {error}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[CreateTheKing] Failed to delete local user '{username}'.");
                return false;
            }
        }

        /// <summary>
        /// Generates a random password.
        /// </summary>
        private string GenerateRandomPassword(int length)
        {
            const string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%";
            const string specialChars = "!@#$%";
            var random = new Random();
            var result = new StringBuilder(length);

            // Ensure at least one of each required character type
            result.Append(char.ToUpper((char)random.Next('a', 'z' + 1))); // Uppercase
            result.Append(char.ToLower((char)random.Next('A', 'Z' + 1))); // Lowercase
            result.Append((char)random.Next('0', '9' + 1)); // Digit
            result.Append(specialChars[random.Next(specialChars.Length)]); // Special char

            for (int i = 4; i < length; i++)
            {
                result.Append(validChars[random.Next(validChars.Length)]);
            }

            // Shuffle the result
            var chars = result.ToString().ToCharArray();
            for (int i = chars.Length - 1; i > 0; i--)
            {
                int j = random.Next(i + 1);
                var temp = chars[i];
                chars[i] = chars[j];
                chars[j] = temp;
            }

            return new string(chars);
        }

        /// <summary>
        /// Generates an encryption key.
        /// </summary>
        private string GenerateEncryptionKey()
        {
            var key = new byte[32]; // 256-bit key
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// Encrypts a password using AES-256.
        /// </summary>
        private string EncryptPassword(string plainPassword, string key)
        {
            var keyBytes = Convert.FromBase64String(key);
            
            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    // Write IV first
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var writer = new StreamWriter(cs))
                    {
                        writer.Write(plainPassword);
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
    }
}
