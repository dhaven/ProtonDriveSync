using System.Collections.Generic;
using System;
using System.IO;
using System.Threading.Tasks;
using ProtonSecrets.Configuration;
using KeePassLib.Keys;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ListView;
using System.Security.Principal;

namespace ProtonSecrets.StorageProvider
{
    public class ProtonDriveStorageProvider
    {
        public ConfigurationService _configService;
        public ProtonAPI _api;

        public ProtonDriveStorageProvider(ConfigurationService configService)
        {
            this._api = new ProtonAPI();
            this._configService = configService;
            if (configService.Account != null)
            {
                this._api.AddAuthHeaders(_configService.Account.UID, _configService.Account.AccessToken);
            }
        }

        public async Task Init()
        {
            await this._api.InitUserKeys(_configService.Account.Email, _configService.Account.KeyPassword);
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

        public async Task<Stream> Save(string path)
        {
            if (this._api.addressKeys == null) await Init();
            return await this._api.Upload();
        }
    }
}