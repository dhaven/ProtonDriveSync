using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using ProtonDriveSync.StorageProvider;
using KeePassLib.Serialization;

namespace ProtonDriveSync.WebRequest
{
    public sealed class ProtonDriveSyncWebRequest : System.Net.WebRequest
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

        public ProtonDriveSyncWebRequest(ProtonDriveStorageProvider provider, string itemPath)
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
                throw new InvalidOperationException(string.Format("ProtonDriveSync: Delete item {0} not supported.", _itemPath));
            }
            else if (this.Method == IOConnection.WrmMoveFile)
            {
                throw new InvalidOperationException(string.Format("ProtonDriveSync: Move item {0} not supported.", _itemPath));
            }
            else if (this.Method == WebRequestMethods.Http.Post)
            {
                var task = Task.Run(async () =>
                {
                    using (var stream = this._requestStream.GetReadableStream())
                    {
                        await _provider.Save(stream, _itemPath);
                    }
                });

                task.Wait();
                if (task.IsFaulted)
                {
                    throw new InvalidOperationException(string.Format("KeeAnywhere: Upload to folder {0} failed",
                        _itemPath), task.Exception);
                }

                _response = new ProtonDriveSyncWebResponse();
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

                _response = new ProtonDriveSyncWebResponse(memoryStream);
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