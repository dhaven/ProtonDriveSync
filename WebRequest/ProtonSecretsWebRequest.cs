using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using ProtonSecrets.StorageProvider;
using KeePassLib.Serialization;

namespace ProtonSecrets.WebRequest
{
    public sealed class ProtonSecretsWebRequest : System.Net.WebRequest
    {
        private readonly ProtonDriveStorageProvider _provider;
        private readonly string _itemPath;

        private RequestStream _requestStream;
        private WebResponse _response;
        private WebHeaderCollection _headers;


        public override ICredentials Credentials { get; set; }
        public override string Method { get; set; }
        public override bool PreAuthenticate { get; set; }
        public override IWebProxy Proxy { get; set; }

        public override WebHeaderCollection Headers
        {
            get
            {
                if (_headers == null)
                    _headers = new WebHeaderCollection();

                return _headers;
            }
            set { _headers = value; }
        }

        public ProtonSecretsWebRequest(ProtonDriveStorageProvider provider, string itemPath)
        {
            if (provider == null) throw new ArgumentNullException("provider");
            if (itemPath == null) throw new ArgumentNullException("itemPath");

            _provider = provider;
            _itemPath = itemPath;
        }


        public override WebResponse GetResponse()
        {
            if (_response != null) return _response;

            if (this.Method == IOConnection.WrmDeleteFile)
            {
                throw new InvalidOperationException(string.Format("ProtonPass: Delete item {0} not supported.", _itemPath));
            }
            else if (this.Method == IOConnection.WrmMoveFile)
            {
                throw new InvalidOperationException(string.Format("ProtonPass: Move item {0} not supported.", _itemPath));
            }
            else // Get File
            {
                var task = Task.Run(async () => await _provider.Load(_itemPath));
                task.Wait();
                var memoryStream = task.Result as MemoryStream;

                if (memoryStream == null)
                {
                    using (task.Result)
                    {
                        memoryStream = new MemoryStream();
                        task.Result.CopyTo(memoryStream);
                        memoryStream.Position = 0;
                    }
                }

                _response = new ProtonSecretsWebResponse(memoryStream);
            }

            return _response;
        }

        public override Stream GetRequestStream()
        {
            if (_requestStream == null)
                _requestStream = new RequestStream(this);

            return _requestStream;
        }
    }
}