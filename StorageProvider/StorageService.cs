using System;
using System.Linq;
using System.Net;
using KeePassLib.Serialization;
using ProtonSecrets.Configuration;
using ProtonSecrets.WebRequest;

namespace ProtonSecrets.StorageProvider
{
    public class StorageService : IWebRequestCreate
    {
        private readonly ConfigurationService _configService;

        public StorageService(ConfigurationService configService)
        {
            if (configService == null) throw new ArgumentNullException("configService");

            _configService = configService;
        }

        public AccountConfiguration CreateAccount()
        {
            var protonDriveConfigurator = new ProtonDriveStorageConfigurator();
            var account = protonDriveConfigurator.CreateAccount();

            return account;
        }

        public System.Net.WebRequest Create(Uri uri)
        {
            //var providerUri = new StorageUri(uri);
            //var provider = this.GetProviderByUri(providerUri);

            var itemPath = GetPath(uri);

            return new ProtonSecretsWebRequest(new ProtonDriveStorageProvider(_configService.Account), itemPath);
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