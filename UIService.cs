using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.UI;
using KeePassLib.Utility;
using ProtonSecrets.Configuration;
using ProtonSecrets.StorageProvider;

namespace ProtonSecrets
{
    public class UIService
    {
        private readonly ConfigurationService _configService;
        private readonly StorageService _storageService;

        public UIService(ConfigurationService configService, StorageService storageService)
        {
            _configService = configService;
            _storageService = storageService;
        }

        public void ShowSettingsDialog()
        {
            var dlg = new ProtonDriveAccountForm();
            var result = UIUtil.ShowDialogAndDestroy(dlg);

            if (result == DialogResult.OK)
                _configService.Account = dlg.Account;
        }
    }
}
