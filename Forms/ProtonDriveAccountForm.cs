using System;
using System.Windows.Forms;
using System.Drawing;
using KeePass.UI;
using ProtonSecrets.Configuration;
using System.Threading.Tasks;

namespace ProtonSecrets.StorageProvider
{
    public class ProtonDriveAccountForm : Form
    {
        private Label m_lblUsername;
        private TextBox m_txtUsername;
        private Label m_lblPassword;
        private TextBox m_txtPassword;
        private Label m_lbl2fa;
        private TextBox m_txt2fa;
        private Button m_btnLogin;
        private Button m_btnDecrypt;
        private GroupBox m_grpCredentials;

        public string Username { get { return m_txtUsername.Text.Trim(); } }
        public string Password { get { return m_txtPassword.Text.Trim(); } }
        public string TwoFA { get { return m_txt2fa.Text.Trim(); } }
        public AccountConfiguration Account;
        private ProtonAPI _api;

        protected bool? TestResult { get; set; }

        public ProtonDriveAccountForm(ProtonAPI api)
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

        private async void OnLogin(object sender, EventArgs e)
        {
            //login the user
            this.Account = await _api.Login(this.Username, this.Password, this.TwoFA);
            //Set TestResult to True if successfully logged in
            if (this.Account != null)
                this.DialogResult = DialogResult.OK;
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (this.DialogResult != DialogResult.OK)
                return;

            if (this.Account == null)
                e.Cancel = true;
        }

        private void InitializeComponent()
        {
            this.m_lblUsername = new Label();
            this.m_txtUsername = new TextBox();
            this.m_lblPassword = new Label();
            this.m_txtPassword = new TextBox();
            this.m_btnLogin = new Button();
            this.m_lbl2fa = new Label();
            this.m_txt2fa = new TextBox();
            this.m_grpCredentials = new GroupBox();
            this.m_grpCredentials.SuspendLayout();
            this.SuspendLayout();

            this.m_lblUsername.AutoSize = true;
            this.m_lblUsername.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            this.m_lblUsername.Location = new Point(6, 22);
            this.m_lblUsername.Name = "m_lblUsername";
            this.m_lblUsername.Size = new Size(73, 13);
            this.m_lblUsername.TabIndex = 0;
            this.m_lblUsername.Text = "Username";

            this.m_txtUsername.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            this.m_txtUsername.Location = new Point(158, 19);
            this.m_txtUsername.Name = "m_txtUsername";
            this.m_txtUsername.Size = new Size(265, 20);
            this.m_txtUsername.TabIndex = 1;

            this.m_lblPassword.AutoSize = true;
            this.m_lblPassword.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            this.m_lblPassword.Location = new Point(6, 48);
            this.m_lblPassword.Name = "m_lblPassword";
            this.m_lblPassword.Size = new Size(69, 13);
            this.m_lblPassword.TabIndex = 2;
            this.m_lblPassword.Text = "Password";

            this.m_txtPassword.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            this.m_txtPassword.Location = new Point(158, 45);
            this.m_txtPassword.Name = "m_txtPassword";
            this.m_txtPassword.Size = new Size(265, 20);
            this.m_txtPassword.TabIndex = 3;

            this.m_lbl2fa.AutoSize = true;
            this.m_lbl2fa.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            this.m_lbl2fa.Location = new Point(6, 74);
            this.m_lbl2fa.Name = "m_lbl2fa";
            this.m_lbl2fa.Size = new Size(69, 13);
            this.m_lbl2fa.TabIndex = 4;
            this.m_lbl2fa.Text = "2fa";

            this.m_txt2fa.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            this.m_txt2fa.Location = new Point(158, 71);
            this.m_txt2fa.Name = "m_txt2fa";
            this.m_txt2fa.Size = new Size(265, 20);
            this.m_txt2fa.TabIndex = 5;

            this.m_btnLogin.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
            this.m_btnLogin.Location = new Point(12, 301);
            this.m_btnLogin.Name = "m_btnLogin";
            this.m_btnLogin.Size = new Size(75, 23);
            this.m_btnLogin.TabIndex = 6;
            this.m_btnLogin.Text = "Login";
            this.m_btnLogin.UseVisualStyleBackColor = true;
            this.m_btnLogin.Click += new EventHandler(this.OnLogin);


            this.m_grpCredentials.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            this.m_grpCredentials.Controls.Add(this.m_lblUsername);
            this.m_grpCredentials.Controls.Add(this.m_txtUsername);
            this.m_grpCredentials.Controls.Add(this.m_lblPassword);
            this.m_grpCredentials.Controls.Add(this.m_txtPassword);
            this.m_grpCredentials.Controls.Add(this.m_lbl2fa);
            this.m_grpCredentials.Controls.Add(this.m_txt2fa);
            this.m_grpCredentials.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            this.m_grpCredentials.Location = new Point(12, 66);
            this.m_grpCredentials.Name = "m_grpCredentials";
            this.m_grpCredentials.Size = new Size(429, 100);
            this.m_grpCredentials.TabIndex = 19;
            this.m_grpCredentials.TabStop = false;
            this.m_grpCredentials.Text = "Credentials";

            this.Controls.Add(this.m_btnLogin);
            this.Controls.Add(this.m_grpCredentials);
            this.AutoScaleDimensions = new SizeF(6F, 13F);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new Size(600, 336);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "Proton Account";
            this.StartPosition = FormStartPosition.CenterParent;
            this.Text = "Authenticate with your Proton account";
            this.FormClosing += new FormClosingEventHandler(this.OnFormClosing);
            this.FormClosed += new FormClosedEventHandler(this.OnFormClosed);
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.m_grpCredentials.ResumeLayout(false);
            this.m_grpCredentials.PerformLayout();
            this.ResumeLayout(false);
        }
    }
}
