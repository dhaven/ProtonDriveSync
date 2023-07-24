using Org.BouncyCastle.Crmf;
using System.Drawing;
using System.Windows.Forms;

namespace ProtonDriveSync.Forms
{
    partial class SignedInAccount
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(SignedInAccount));
            this.lbl_connectedTo = new System.Windows.Forms.Label();
            this.lbl_email = new System.Windows.Forms.Label();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.btn_logout = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // lbl_connectedTo
            // 
            this.lbl_connectedTo.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.lbl_connectedTo.AutoSize = true;
            this.lbl_connectedTo.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lbl_connectedTo.Location = new System.Drawing.Point(235, 42);
            this.lbl_connectedTo.Name = "lbl_connectedTo";
            this.lbl_connectedTo.Size = new System.Drawing.Size(97, 18);
            this.lbl_connectedTo.TabIndex = 1;
            this.lbl_connectedTo.Text = "Connected to";
            // 
            // lbl_email
            // 
            this.lbl_email.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.lbl_email.AutoSize = true;
            this.lbl_email.Font = new System.Drawing.Font("Microsoft Sans Serif", 11F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lbl_email.Name = "lbl_email";
            this.lbl_email.TabIndex = 2;
            this.lbl_email.Text = this.Email;
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = ((System.Drawing.Image)(resources.GetObject("pictureBox1.Image")));
            this.pictureBox1.Location = new System.Drawing.Point(253, 117);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(52, 54);
            this.pictureBox1.TabIndex = 3;
            this.pictureBox1.TabStop = false;
            // 
            // btn_logout
            // 
            this.btn_logout.Location = new System.Drawing.Point(174, 231);
            this.btn_logout.Name = "btn_logout";
            this.btn_logout.Size = new System.Drawing.Size(212, 34);
            this.btn_logout.TabIndex = 4;
            this.btn_logout.Text = "Log out";
            this.btn_logout.UseVisualStyleBackColor = true;
            this.btn_logout.Click += new System.EventHandler(this.OnLogout);
            // 
            // SignedInAccount
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(559, 300);
            this.Controls.Add(this.btn_logout);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.lbl_email);
            this.Controls.Add(this.lbl_connectedTo);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Name = "SignedInAccount";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Proton account connection";
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();
            this.lbl_email.Left = (this.ClientSize.Width - this.lbl_email.Width) / 2;
            this.lbl_email.Top = 72;

        }

        #endregion
        private System.Windows.Forms.Label lbl_connectedTo;
        private System.Windows.Forms.Label lbl_email;
        private System.Windows.Forms.PictureBox pictureBox1;
        private Button btn_logout;
    }
}