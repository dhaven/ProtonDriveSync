using System;
using System.Windows.Forms;
using System.Drawing;
using KeePass.UI;
using ProtonDriveSync.Configuration;
using ProtonDriveSync.StorageProvider;
using KeePassLib.Utility;

namespace ProtonDriveSync.Forms
{
    public class ProtonDriveAccountForm : Form
    {
        private Label lbl_email;
        private TextBox txt_email;
        private TextBox txt_password;
        private Label lbl_password;
        private Button btn_signin;
        private Label lbl_title;
        private GroupBox logingroup;

        public string Username { get { return txt_email.Text.Trim(); } }
        public string Password { get { return txt_password.Text.Trim(); } }
        public AccountConfiguration Account;
        private ProtonDriveStorageProvider _provider;
        private Cursor m_savedCursor;

        public ProtonDriveAccountForm(ProtonDriveStorageProvider provider)
        {
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

        private async void OnLogin(object sender, EventArgs e)
        {
            //login the user
            try
            {
                SetWaitState(true);
                this.Account = await _provider._api.Authenticate(this.Username, this.Password);
                if (this.Account.Is2faEnabled)
                {
                    var form = new ProtonDrive2FA(_provider._api);
                    var result = UIUtil.ShowDialogAndDestroy(form);

                    if (result != DialogResult.OK)
                    {
                        SetWaitState(false);
                        return;
                    }
                }
                this.Account.KeyPassword = await _provider._api.ComputeKeyPassword(this.Password);
                this.DialogResult = DialogResult.OK;
                MessageService.ShowInfo("Successfully logged in.");
                SetWaitState(false);
            }
            catch(Exception exception)
            {
                SetWaitState(false);
                MessageService.ShowFatal(exception.Message);
            }
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (this.DialogResult != DialogResult.OK)
                return;

            if (this.Account == null)
                e.Cancel = true;
        }

        private void SetWaitState(bool isWait)
        {
            if (isWait && m_savedCursor != null) return;

            txt_email.Enabled = !isWait;
            txt_password.Enabled = !isWait;
            btn_signin.Enabled = !isWait;

            if (isWait)
            {
                m_savedCursor = Cursor;
                Cursor = Cursors.WaitCursor;
            }
            else
            {
                Cursor = m_savedCursor;
                m_savedCursor = null;
            }
        }

        private void InitializeComponent()
        {
            this.lbl_email = new Label();
            this.txt_email = new TextBox();
            this.txt_password = new TextBox();
            this.lbl_password = new Label();
            this.btn_signin = new Button();
            this.lbl_title = new Label();
            this.logingroup = new GroupBox();
            this.logingroup.SuspendLayout();
            this.SuspendLayout();

            this.lbl_email.AutoSize = true;
            this.lbl_email.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.lbl_email.Location = new Point(26, 33);
            this.lbl_email.Name = "lbl_email";
            this.lbl_email.Size = new Size(60, 25);
            this.lbl_email.Text = "Email";

            this.txt_email.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.txt_email.Location = new Point(31, 61);
            this.txt_email.Name = "txt_email";
            this.txt_email.Size = new Size(216, 32);
            this.txt_email.TabIndex = 0;

            this.lbl_password.AutoSize = true;
            this.lbl_password.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.lbl_password.Location = new Point(26, 112);
            this.lbl_password.Name = "lbl_password";
            this.lbl_password.Size = new Size(98, 25);
            this.lbl_password.Text = "Password";

            this.txt_password.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.txt_password.Location = new Point(31, 140);
            this.txt_password.Name = "txt_password";
            this.txt_password.Size = new Size(216, 32);
            this.txt_password.TabIndex = 1;

            this.btn_signin.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.btn_signin.Location = new Point(31, 213);
            this.btn_signin.Name = "btn_signin";
            this.btn_signin.Size = new Size(216, 38);
            this.btn_signin.TabIndex = 2;
            this.btn_signin.Text = "Sign in";
            this.btn_signin.UseVisualStyleBackColor = true;
            this.btn_signin.Click += new EventHandler(this.OnLogin);

            this.lbl_title.AutoSize = true;
            this.lbl_title.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Regular, GraphicsUnit.Point, ((byte)(0)));
            this.lbl_title.Location = new Point(12, 28);
            this.lbl_title.MaximumSize = new Size(500, 0);
            this.lbl_title.Name = "lbl_title";
            this.lbl_title.Size = new Size(613, 65);
            this.lbl_title.Text = "Connect with your Proton account to access your KDBX files stored in ProtonDrive.";

            this.logingroup.Controls.Add(this.lbl_email);
            this.logingroup.Controls.Add(this.txt_email);
            this.logingroup.Controls.Add(this.btn_signin);
            this.logingroup.Controls.Add(this.lbl_password);
            this.logingroup.Controls.Add(this.txt_password);
            this.logingroup.Location = new Point(173, 109);
            this.logingroup.Name = "logingroup";
            this.logingroup.Size = new Size(288, 292);
            this.logingroup.TabIndex = 6;
            this.logingroup.TabStop = false;

            this.AutoScaleDimensions = new SizeF(8F, 16F);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(640, 434);
            this.StartPosition = FormStartPosition.CenterParent;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.Controls.Add(this.logingroup);
            this.Controls.Add(this.lbl_title);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "signinform";
            this.Text = "Sign in";
            this.FormClosing += new FormClosingEventHandler(this.OnFormClosing);
            this.FormClosed += new FormClosedEventHandler(this.OnFormClosed);
            this.Load += new EventHandler(this.OnFormLoad);
            this.logingroup.ResumeLayout(false);
            this.logingroup.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }
}
