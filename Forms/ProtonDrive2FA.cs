using KeePass.UI;
using ProtonSecrets.Configuration;
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
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace ProtonSecrets.Forms
{
    public partial class ProtonDrive2FA : Form
    {

        public string TwoFA { get { return txt_2fa_1.Text.Trim() + txt_2fa_2.Text.Trim() + txt_2fa_3.Text.Trim() + txt_2fa_4.Text.Trim() + txt_2fa_5.Text.Trim() + txt_2fa_6.Text.Trim(); } }
        public AccountConfiguration Account;
        private ProtonAPI _api;

        public ProtonDrive2FA(ProtonAPI api)
        {
            InitializeComponent();
            _api = api;
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);
        }

        private void OnFormClosed(object sender, FormClosedEventArgs e)
        {
            GlobalWindowManager.RemoveWindow(this);
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (this.DialogResult != DialogResult.OK)
                return;
        }

        private async void OnAuthenticate(object sender, EventArgs e)
        {
            await _api.Validate2fa(this.TwoFA);
            this.DialogResult = DialogResult.OK;
        }

        private void txt_2fa_1_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_1.Text.Length == 1)
            {
                txt_2fa_2.Focus();
            }
        }

        private void txt_2fa_2_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_2.Text.Length == 1)
            {
                txt_2fa_3.Focus();
            }
        }

        private void txt_2fa_3_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_3.Text.Length == 1)
            {
                txt_2fa_4.Focus();
            }
        }

        private void txt_2fa_4_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_4.Text.Length == 1)
            {
                txt_2fa_5.Focus();
            }
        }

        private void txt_2fa_5_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_5.Text.Length == 1)
            {
                txt_2fa_6.Focus();
            }
        }

        private void txt_2fa_6_TextChanged(object sender, EventArgs e)
        {
            if (txt_2fa_6.Text.Length == 1)
            {
                btn_auth.Focus();
            }
        }
    }
}
