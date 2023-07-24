namespace ProtonDriveSync.Forms
{
    partial class ProtonDriveFilePicker
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
            this.components = new System.ComponentModel.Container();
            this.m_btnOk = new System.Windows.Forms.Button();
            this.m_btnCancel = new System.Windows.Forms.Button();
            this.m_lvDetails = new System.Windows.Forms.ListView();
            this.m_ilFiletypeIcons = new System.Windows.Forms.ImageList(this.components);
            this.m_lblFilename = new System.Windows.Forms.Label();
            this.m_txtFilename = new System.Windows.Forms.TextBox();
            this.m_cbFilter = new System.Windows.Forms.ComboBox();
            this.SuspendLayout();
            // 
            // m_btnOk
            // 
            this.m_btnOk.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.m_btnOk.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.m_btnOk.Location = new System.Drawing.Point(560, 398);
            this.m_btnOk.Margin = new System.Windows.Forms.Padding(4);
            this.m_btnOk.Name = "m_btnOk";
            this.m_btnOk.Size = new System.Drawing.Size(100, 28);
            this.m_btnOk.TabIndex = 8;
            this.m_btnOk.Text = "OK";
            this.m_btnOk.UseVisualStyleBackColor = true;
            this.m_btnOk.Click += new System.EventHandler(this.OnOkClick);
            // 
            // m_btnCancel
            // 
            this.m_btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.m_btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.m_btnCancel.Location = new System.Drawing.Point(668, 398);
            this.m_btnCancel.Margin = new System.Windows.Forms.Padding(4);
            this.m_btnCancel.Name = "m_btnCancel";
            this.m_btnCancel.Size = new System.Drawing.Size(100, 28);
            this.m_btnCancel.TabIndex = 9;
            this.m_btnCancel.Text = "Cancel";
            this.m_btnCancel.UseVisualStyleBackColor = true;
            // 
            // m_lvDetails
            // 
            this.m_lvDetails.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.m_lvDetails.FullRowSelect = true;
            this.m_lvDetails.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.m_lvDetails.HideSelection = false;
            this.m_lvDetails.Location = new System.Drawing.Point(20, 13);
            this.m_lvDetails.Margin = new System.Windows.Forms.Padding(4);
            this.m_lvDetails.MultiSelect = false;
            this.m_lvDetails.Name = "m_lvDetails";
            this.m_lvDetails.Size = new System.Drawing.Size(747, 328);
            this.m_lvDetails.SmallImageList = this.m_ilFiletypeIcons;
            this.m_lvDetails.TabIndex = 12;
            this.m_lvDetails.UseCompatibleStateImageBehavior = false;
            this.m_lvDetails.View = System.Windows.Forms.View.Details;
            this.m_lvDetails.ItemSelectionChanged += new System.Windows.Forms.ListViewItemSelectionChangedEventHandler(this.OnItemSelectionChanged);
            this.m_lvDetails.DoubleClick += new System.EventHandler(this.OnItemDoubleClick);
            // 
            // m_ilFiletypeIcons
            // 
            this.m_ilFiletypeIcons.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
            this.m_ilFiletypeIcons.ImageSize = new System.Drawing.Size(16, 16);
            this.m_ilFiletypeIcons.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // m_lblFilename
            // 
            this.m_lblFilename.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.m_lblFilename.AutoSize = true;
            this.m_lblFilename.Location = new System.Drawing.Point(16, 354);
            this.m_lblFilename.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.m_lblFilename.Name = "m_lblFilename";
            this.m_lblFilename.Size = new System.Drawing.Size(32, 16);
            this.m_lblFilename.TabIndex = 13;
            this.m_lblFilename.Text = "File:";
            // 
            // m_txtFilename
            // 
            this.m_txtFilename.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.m_txtFilename.Location = new System.Drawing.Point(91, 350);
            this.m_txtFilename.Margin = new System.Windows.Forms.Padding(4);
            this.m_txtFilename.Name = "m_txtFilename";
            this.m_txtFilename.Size = new System.Drawing.Size(460, 22);
            this.m_txtFilename.TabIndex = 14;
            // 
            // m_cbFilter
            // 
            this.m_cbFilter.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.m_cbFilter.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.m_cbFilter.FormattingEnabled = true;
            this.m_cbFilter.Location = new System.Drawing.Point(560, 350);
            this.m_cbFilter.Margin = new System.Windows.Forms.Padding(4);
            this.m_cbFilter.Name = "m_cbFilter";
            this.m_cbFilter.Size = new System.Drawing.Size(207, 24);
            this.m_cbFilter.TabIndex = 15;
            this.m_cbFilter.SelectedIndexChanged += new System.EventHandler(this.OnFilterChanged);
            // 
            // ProtonDriveFilePicker
            // 
            this.AcceptButton = this.m_btnOk;
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.m_btnCancel;
            this.ClientSize = new System.Drawing.Size(784, 441);
            this.Controls.Add(this.m_cbFilter);
            this.Controls.Add(this.m_txtFilename);
            this.Controls.Add(this.m_lblFilename);
            this.Controls.Add(this.m_lvDetails);
            this.Controls.Add(this.m_btnOk);
            this.Controls.Add(this.m_btnCancel);
            this.Margin = new System.Windows.Forms.Padding(4);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "ProtonDriveFilePicker";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.Text = "Select database file";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.OnFormClosed);
            this.Load += new System.EventHandler(this.OnFormLoad);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button m_btnOk;
        private System.Windows.Forms.Button m_btnCancel;
        private System.Windows.Forms.ListView m_lvDetails;
        private System.Windows.Forms.Label m_lblFilename;
        private System.Windows.Forms.TextBox m_txtFilename;
        private System.Windows.Forms.ComboBox m_cbFilter;
        private System.Windows.Forms.ImageList m_ilFiletypeIcons;
    }
}