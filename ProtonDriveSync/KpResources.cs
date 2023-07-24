using KeePass.Plugins;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProtonDriveSync
{
    public class KpResources
    {
        private IPluginHost _host;

        public KpResources(IPluginHost host)
        {
            _host = host;
        }

        public Bitmap B16x16_KeePass
        {
            get { return (Bitmap)_host.Resources.GetObject("B16x16_KeePass"); }
        }

        public Bitmap B16x16_Folder
        {
            get { return (Bitmap)_host.Resources.GetObject("B16x16_Folder"); }
        }

        public Bitmap B16x16_Binary
        {
            get { return (Bitmap)_host.Resources.GetObject("B16x16_Binary"); }
        }
    }
}
