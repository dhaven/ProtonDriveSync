using System.Collections.Generic;
using System;
using System.IO;
using System.Threading.Tasks;
using ProtonSecrets.Configuration;
using KeePassLib.Keys;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ListView;

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
            this._api.addAuthHeaders(account.UID, account.AccessToken);
        }

        public async Task Init()
        {
            await this._api.InitUserKeys(account.Email, account.KeyPassword);
        }

        // Responsible for downloading a file at the given path from ProtonDrive
        public async Task<Stream> Load(string path)
        {
            if (this._api.addressKeys == null) await Init();
            return await this._api.Download(path);
        }

        public async Task<IEnumerable<ProtonDriveItem>> GetRootItem()
        {
            return await _api.GetRootChildren();
        }

        public async Task<IEnumerable<ProtonDriveItem>> GetChildrenForItem(ProtonDriveItem item)
        {
            if (item == null) throw new ArgumentNullException("item");

            return await _api.GetChildren(item.ParentKeys, item.Id, item.ShareId);
        }
    }
}