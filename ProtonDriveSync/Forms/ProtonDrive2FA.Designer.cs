using System;
using System.Windows.Forms;

namespace ProtonDriveSync.Forms
{
    partial class ProtonDrive2FA
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
            this.lbl_title = new System.Windows.Forms.Label();
            this.txt_2fa_2 = new System.Windows.Forms.TextBox();
            this.txt_2fa_3 = new System.Windows.Forms.TextBox();
            this.txt_2fa_6 = new System.Windows.Forms.TextBox();
            this.txt_2fa_5 = new System.Windows.Forms.TextBox();
            this.txt_2fa_4 = new System.Windows.Forms.TextBox();
            this.txt_2fa_1 = new System.Windows.Forms.TextBox();
            this.btn_auth = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // lbl_title
            // 
            this.lbl_title.AutoSize = true;
            this.lbl_title.Location = new System.Drawing.Point(138, 83);
            this.lbl_title.Name = "lbl_title";
            this.lbl_title.Size = new System.Drawing.Size(257, 16);
            this.lbl_title.TabIndex = 0;
            this.lbl_title.Text = "Enter the code from your authenticator app";
            // 
            // txt_2fa_2
            // 
            this.txt_2fa_2.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_2.Location = new System.Drawing.Point(182, 116);
            this.txt_2fa_2.MaxLength = 1;
            this.txt_2fa_2.Name = "txt_2fa_2";
            this.txt_2fa_2.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_2.TabIndex = 1;
            this.txt_2fa_2.TextChanged += new System.EventHandler(this.txt_2fa_2_TextChanged);
            // 
            // txt_2fa_3
            // 
            this.txt_2fa_3.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_3.Location = new System.Drawing.Point(223, 116);
            this.txt_2fa_3.MaxLength = 1;
            this.txt_2fa_3.Name = "txt_2fa_3";
            this.txt_2fa_3.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_3.TabIndex = 2;
            this.txt_2fa_3.TextChanged += new System.EventHandler(this.txt_2fa_3_TextChanged);
            // 
            // txt_2fa_6
            // 
            this.txt_2fa_6.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_6.Location = new System.Drawing.Point(362, 116);
            this.txt_2fa_6.MaxLength = 1;
            this.txt_2fa_6.Name = "txt_2fa_6";
            this.txt_2fa_6.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_6.TabIndex = 5;
            this.txt_2fa_6.TextChanged += new System.EventHandler(this.txt_2fa_6_TextChanged);
            // 
            // txt_2fa_5
            // 
            this.txt_2fa_5.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_5.Location = new System.Drawing.Point(321, 116);
            this.txt_2fa_5.MaxLength = 1;
            this.txt_2fa_5.Name = "txt_2fa_5";
            this.txt_2fa_5.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_5.TabIndex = 4;
            this.txt_2fa_5.TextChanged += new System.EventHandler(this.txt_2fa_5_TextChanged);
            // 
            // txt_2fa_4
            // 
            this.txt_2fa_4.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_4.Location = new System.Drawing.Point(280, 116);
            this.txt_2fa_4.MaxLength = 1;
            this.txt_2fa_4.Name = "txt_2fa_4";
            this.txt_2fa_4.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_4.TabIndex = 3;
            this.txt_2fa_4.TextChanged += new System.EventHandler(this.txt_2fa_4_TextChanged);
            // 
            // txt_2fa_1
            // 
            this.txt_2fa_1.Font = new System.Drawing.Font("Microsoft Sans Serif", 13F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txt_2fa_1.Location = new System.Drawing.Point(141, 116);
            this.txt_2fa_1.MaxLength = 1;
            this.txt_2fa_1.Name = "txt_2fa_1";
            this.txt_2fa_1.Size = new System.Drawing.Size(35, 32);
            this.txt_2fa_1.TabIndex = 0;
            this.txt_2fa_1.TextChanged += new System.EventHandler(this.txt_2fa_1_TextChanged);
            // 
            // btn_auth
            // 
            this.btn_auth.Location = new System.Drawing.Point(141, 179);
            this.btn_auth.Name = "btn_auth";
            this.btn_auth.Size = new System.Drawing.Size(256, 39);
            this.btn_auth.TabIndex = 6;
            this.btn_auth.Text = "Authenticate";
            this.btn_auth.UseVisualStyleBackColor = true;
            this.btn_auth.Click += new System.EventHandler(this.OnAuthenticate);
            // 
            // ProtonDrive2FA
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(528, 326);
            this.Controls.Add(this.btn_auth);
            this.Controls.Add(this.txt_2fa_1);
            this.Controls.Add(this.txt_2fa_6);
            this.Controls.Add(this.txt_2fa_5);
            this.Controls.Add(this.txt_2fa_4);
            this.Controls.Add(this.txt_2fa_3);
            this.Controls.Add(this.txt_2fa_2);
            this.Controls.Add(this.lbl_title);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "ProtonDrive2FA";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Two-factor authentication";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.OnFormClosed);
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lbl_title;
        private System.Windows.Forms.TextBox txt_2fa_2;
        private System.Windows.Forms.TextBox txt_2fa_3;
        private System.Windows.Forms.TextBox txt_2fa_6;
        private System.Windows.Forms.TextBox txt_2fa_5;
        private System.Windows.Forms.TextBox txt_2fa_4;
        private System.Windows.Forms.TextBox txt_2fa_1;
        private System.Windows.Forms.Button btn_auth;
    }
}