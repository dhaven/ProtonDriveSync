using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PgpCore;

namespace ProtonSecrets.StorageProvider
{
    public class ProtonDriveItem
    {
        public StorageProviderItemType Type { get; set; }

        public string Id { get; set; }
        public string Name { get; set; }

        public string ShareId { get; set; }

        public  PGP ParentKeys { get; set; }

        public DateTimeOffset? LastModifiedDateTime { get; set; }

    }
}
