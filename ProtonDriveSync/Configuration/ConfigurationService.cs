using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using CredentialManagement;

namespace ProtonDriveSync.Configuration
{
    public class ConfigurationService
    {

        public AccountConfiguration Account { get; set; }
        public bool IsLoaded { get; set; }

        public void Revoke()
        {
            var credentialSet = new CredentialSet();
            credentialSet.Load();
            var credential = credentialSet.Find(c => c.Target.StartsWith("Keepass:ProtonDriveSyncPlugin"));
            if(credential != null)
            {
                credential.Delete();
            }
        }

        public void LoadAccountsFromWindowsCredentialManager()
        {
            if (IsLoaded)
                return;

            var credentialSet = new CredentialSet();
            credentialSet.Load();
            var credential = credentialSet.Find(c => c.Target.StartsWith("Keepass:ProtonDriveSyncPlugin"));
            if (credential == null)
                return;
            JObject bodyData = JObject.Parse(credential.Password);
            this.Account = new AccountConfiguration((string)bodyData["KeyPassword"], (string)bodyData["Email"], (string)bodyData["UID"], (string)bodyData["AccessToken"], (string)bodyData["RefreshToken"], false);
            IsLoaded = true;
        }

        public void SaveAccountsToWindowsCredentialManager()
        {
            JObject sessionData = new JObject();
            sessionData["KeyPassword"] = new JValue((string)this.Account.KeyPassword);
            sessionData["Email"] = new JValue((string)this.Account.Email);
            sessionData["UID"] = new JValue((string)this.Account.UID);
            sessionData["AccessToken"] = new JValue((string)this.Account.AccessToken);
            sessionData["RefreshToken"] = new JValue((string)this.Account.RefreshToken);
            var configString = JsonConvert.SerializeObject(sessionData);
            var credential = new Credential
            {
                Target = "Keepass:ProtonDriveSyncPlugin",
                Username = this.Account.Email,
                Password = configString,
                PersistanceType = PersistanceType.LocalComputer,
                Type = CredentialType.Generic,
                Description = "Credentials required to access Proton account from the Keepass plugin ProtonDriveSync"
            };
            credential.Save();
        }
    }
}