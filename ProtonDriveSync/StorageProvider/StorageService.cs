using System;
using System.Linq;
using System.Net;
using KeePassLib.Serialization;
using ProtonDriveSync.WebRequest;

namespace ProtonDriveSync.StorageProvider
{
    public class StorageService : IWebRequestCreate
    {
        public ProtonDriveStorageProvider _storageProvider { get; set; }

        public StorageService(ProtonDriveStorageProvider storageProvider)
        {
            _storageProvider = storageProvider;
        }

        public System.Net.WebRequest Create(Uri uri)
        {
            //var providerUri = new StorageUri(uri);
            //var provider = this.GetProviderByUri(providerUri);

            var itemPath = GetPath(uri);

            return new ProtonDriveSyncWebRequest(_storageProvider, itemPath);
        }

        public void RegisterPrefixes()
        {
            FileTransactionEx.Configure("proton", false);
            System.Net.WebRequest.RegisterPrefix("proton:", this);
            
        }

        public string GetPath(Uri uri)
        {
            var segments = uri.OriginalString.Split('/');
            if (segments.Length < 4)
                return null;

            segments = segments.Where((val, idx) => idx >= 3).ToArray();

            var path = string.Join("/", segments);
            path = Uri.UnescapeDataString(path);
            return path;
        }
    }
}