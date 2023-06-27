using KeePass.UI;
using KeePassLib.Utility;
using ProtonSecrets.StorageProvider;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProtonSecrets.Forms
{
    public partial class SignedInAccount : Form
    {
        private string Email = "";
        private ProtonDriveStorageProvider _provider;

        public SignedInAccount(string email, ProtonDriveStorageProvider provider)
        {
            this.Email = email;
            _provider = provider;
            InitializeComponent();
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);
        }

        private void OnFormClosed(object sender, FormClosedEventArgs e)
        {
            GlobalWindowManager.RemoveWindow(this);
        }

        private async void OnLogout(object sender, EventArgs e)
        {
            try
            {
                await _provider._api.Logout();
                _provider._configService.Revoke();
                MessageService.ShowInfo("Successfully logged out.");
                this.DialogResult = DialogResult.OK;
            }
            catch(Exception exception)
            {
                MessageService.ShowFatal(exception.Message);
            }
        }
    }
}
