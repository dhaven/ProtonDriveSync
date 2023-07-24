using System;
using System.IO;
using System.Net;

namespace ProtonDriveSync.WebRequest
{
    public sealed class ProtonDriveSyncWebResponse : WebResponse
    {
        private readonly Stream _stream;

        public override long ContentLength { get; set; }

        public ProtonDriveSyncWebResponse()
        {
        }

        public ProtonDriveSyncWebResponse(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException("stream");

            _stream = stream;
            //try
            //{
            //    this.ContentLength = _stream.Length;
            //}
            //catch (NotSupportedException)
            //{
            this.ContentLength = -1;
            //}
        }

        public override Stream GetResponseStream()
        {
            return _stream;
        }

    }
}
