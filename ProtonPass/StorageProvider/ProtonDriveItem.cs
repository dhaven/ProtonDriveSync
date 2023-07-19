using System;

using PgpCore;

namespace ProtonPass.StorageProvider
{
    public class ProtonDriveItem
    {
        public StorageProviderItemType Type { get; set; }

        public string Size { get; set; }
        public string Name { get; set; }

        public string Id { get; set; }

        public string ShareId { get; set; }

        public  PGP ParentKeys { get; set; }

        public DateTimeOffset? LastModifiedDateTime { get; set; }

    }
}
