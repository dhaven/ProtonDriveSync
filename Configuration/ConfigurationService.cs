using System;
using System.IO;
using System.Reflection;

using KeePass.App.Configuration;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ProtonSecrets.Configuration
{
    public class ConfigurationService
    {
        private const string ConfigurationFile_Accounts = "ProtonPass.Accounts.json";

        public AccountConfiguration Account { get; set; }
        public bool IsLoaded { get; set; }


        public void Load()
        {
            if (IsLoaded) 
                return;

            var path = ConfigurationInfo();
            var filename = Path.Combine(path, ConfigurationFile_Accounts);
            if (!File.Exists(filename))
                return;
            var configString = File.ReadAllText(filename);
            if (string.IsNullOrEmpty(configString)) 
                return;
            JObject bodyData = JObject.Parse(configString);
            this.Account = new AccountConfiguration((string)bodyData["KeyPassword"], (string)bodyData["Email"], (string)bodyData["UID"], (string)bodyData["AccessToken"], (string)bodyData["RefreshToken"], false);
            IsLoaded = true;
        }

        public void Save()
        {
            var path = ConfigurationInfo();
            var filename = Path.Combine(path, ConfigurationFile_Accounts);
            JObject sessionData = new JObject();
            sessionData["KeyPassword"] = new JValue((string)this.Account.KeyPassword);
            sessionData["Email"] = new JValue((string)this.Account.Email);
            sessionData["UID"] = new JValue((string)this.Account.UID);
            sessionData["AccessToken"] = new JValue((string)this.Account.AccessToken);
            sessionData["RefreshToken"] = new JValue((string)this.Account.RefreshToken);
            var configString = JsonConvert.SerializeObject(sessionData);

            File.WriteAllText(filename, configString);
        }

        public void Revoke()
        {
            var path = ConfigurationInfo();
            var filename = Path.Combine(path, ConfigurationFile_Accounts);
            File.Delete(filename);
        }

        private string ConfigurationInfo()
        {
            var isGlobalConfig = !KeePass.Program.Config.Meta.PreferUserConfiguration;
            var asm = Assembly.GetEntryAssembly();
            var filename = asm.Location;
            var directory = Path.GetDirectoryName(filename);

            bool _isPortable = isGlobalConfig
                && !directory.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))
                && !directory.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            if (_isPortable)
            {
                return directory;
            }
            else
            {
                return AppConfigSerializer.AppDataDirectory;
            }
        }
    }
}