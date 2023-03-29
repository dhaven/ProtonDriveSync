using System.Windows.Forms;
using ProtonSecrets.Configuration;
using KeePass.UI;

namespace ProtonSecrets.StorageProvider
{
    public class ProtonDriveStorageConfigurator
    {
        //authenticate the user with the ProtonDrive storage provider
        public AccountConfiguration CreateAccount()
        {
            var dlg = new ProtonDriveAccountForm();
            var result = UIUtil.ShowDialogAndDestroy(dlg);

            if (result != DialogResult.OK)
                return null;

            return dlg.Account;
        }
    }
}
