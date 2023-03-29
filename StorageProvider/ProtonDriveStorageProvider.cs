using System.IO;
using System.Threading.Tasks;
using ProtonSecrets.Configuration;

namespace ProtonSecrets.StorageProvider
{
    public class ProtonDriveStorageProvider
    {
        private readonly AccountConfiguration account;
        private ProtonAPI _api;

        public ProtonDriveStorageProvider(AccountConfiguration account)
        {
            this.account = account;
            this._api = new ProtonAPI();
        }

        // Responsible for downloading a file at the given path from ProtonDrive
        public async Task<Stream> Load(string path)
        {
            // account has the info we need to auth the request
            _api.addAuthHeaders(this.account.UID, this.account.AccessToken);
            return await this._api.Download(path, this.account.Email, this.account.KeyPassword);
        }
    }
}