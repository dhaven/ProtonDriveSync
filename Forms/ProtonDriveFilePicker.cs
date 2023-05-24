﻿using KeePass.UI;
using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using ProtonSecrets.Configuration;
using ProtonSecrets.StorageProvider;
using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Tab;
using Org.BouncyCastle.Asn1.Ocsp;

namespace ProtonSecrets.Forms
{
    public partial class ProtonDriveFilePicker : Form
    {
        private const string IconFolder = "folder";
        private const string IconDatabase = "database";
        private const string IconDocument = "document";
        public enum Mode
        {
            Unknown,
            Open,
            Save,
        }
        private ConfigurationService m_configService;
        private bool m_isInit;
        private StorageService _storageService;
        private ProtonDriveStorageProvider _provider;
        private Mode _mode;
        private IEnumerable<ProtonDriveItem> m_selectedItem;
        private readonly Stack<IEnumerable<ProtonDriveItem>> m_stack = new Stack<IEnumerable<ProtonDriveItem>>();
        private string folderPath;
        private KpResources _kpResources;

        public string ResultUri
        {
            get
            {
                return GetFilePath();
            }
        }

        public ProtonDriveFilePicker(StorageService storageService, KpResources kpResources, Mode mode)
        {
            _storageService = storageService;
            _kpResources = kpResources;
            _mode = mode;
            folderPath = "";
            InitializeComponent();
        }

        private async void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);

            m_isInit = true;

            m_ilFiletypeIcons.Images.Add(IconFolder, _kpResources.B16x16_Folder);
            m_ilFiletypeIcons.Images.Add(IconDatabase, _kpResources.B16x16_KeePass);
            m_ilFiletypeIcons.Images.Add(IconDocument, _kpResources.B16x16_Binary);

            m_cbFilter.Items.Add("KeePass KDBX Files (*.kdbx)");
            m_cbFilter.Items.Add("All Files (*.*)");
            m_cbFilter.SelectedIndex = 0;

            m_lvDetails.Columns.Add("Name");
            m_lvDetails.Columns.Add("Size");
            m_lvDetails.Columns.Add("Type");
            m_lvDetails.Columns.Add("Changed Date");

            UIUtil.ResizeColumns(m_lvDetails, new int[] {
                3, 1, 1, 2 }, true);

            m_isInit = false;

            try
            {
                m_selectedItem = await _storageService._storageProvider.GetRootItem();
                //m_stack.Push(m_selectedItem);
            }
            catch (Exception ex)
            {
                MessageService.ShowWarning("Error getting Root node.\r\nException:", ex);
            }
            await UpdateListView();
            m_txtFilename.Text = GetFilePath();
        }

        private async void OnOkClick(object sender, EventArgs e)
        {
            DialogResult = DialogResult.None;
            if (string.IsNullOrEmpty(m_txtFilename.Text)) return;

            ProtonDriveItem subItem = m_selectedItem.SingleOrDefault(_ => _.Name == m_txtFilename.Text);
            switch (_mode)
            {
                case Mode.Open:
                    if (subItem == null)
                    {
                        return;
                    }
                    else
                    {
                        switch (subItem.Type)
                        {
                            case StorageProviderItemType.File:
                                DialogResult = DialogResult.OK;
                                break;

                            case StorageProviderItemType.Folder:
                                m_stack.Push(m_selectedItem);
                                PushFolder(subItem.Name);
                                m_txtFilename.Text = "";
                                m_selectedItem = await _storageService._storageProvider.GetChildrenForItem(subItem);
                                await UpdateListView();
                                break;
                        }
                    }
                    break;
                case Mode.Save:
          
                    if (subItem == null)
                    {
                        DialogResult = DialogResult.OK;
                    }
                    else
                    {
                        switch (subItem.Type)
                        {
                            case StorageProviderItemType.File:
                                DialogResult = DialogResult.OK;
                                break;
            
                        }
                    }

                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        private void OnFormClosed(object sender, FormClosedEventArgs e)
        {
            GlobalWindowManager.RemoveWindow(this);
        }

        private async Task UpdateListView()
        {
            m_lvDetails.BeginUpdate();
            m_lvDetails.Items.Clear();
            if (m_selectedItem == null)
            {
                m_lvDetails.EndUpdate();
                return;
            }
            if (m_stack.Count() > 0)
            {
                var lvi = m_lvDetails.Items.Add("..");
                ProtonDriveItem parentDummyItem = new ProtonDriveItem();
                parentDummyItem.Type = StorageProviderItemType.Folder;
                lvi.Tag = parentDummyItem;
                lvi.ImageKey = IconFolder;
                lvi.SubItems.Add("-");
                lvi.SubItems.Add("Folder");
                lvi.SubItems.Add(string.Empty);
            }
            foreach (var child in m_selectedItem)
            {
                var ext = Path.GetExtension(child.Name);
                if (m_cbFilter.SelectedIndex == 0 && child.Type == StorageProviderItemType.File && (string.IsNullOrEmpty(ext) || ext.ToLower() != ".kdbx"))
                    continue;

                var lvi = m_lvDetails.Items.Add(child.Name);
                lvi.Tag = child;
                lvi.SubItems.Add(child.Size == null? "-": child.Size);
                switch (child.Type)
                {
                    case StorageProviderItemType.Folder:
                        lvi.ImageKey = IconFolder;
                        lvi.SubItems.Add("Folder");
                        break;
                    case StorageProviderItemType.File:
                        lvi.ImageKey = GetIconKey(child.Name);
                        lvi.SubItems.Add("File");
                        break;
                    default:
                        lvi.SubItems.Add("Unknown");
                        break;
                }
                lvi.SubItems.Add(child.LastModifiedDateTime.HasValue ? child.LastModifiedDateTime.Value.LocalDateTime.ToString() : null);
            }
            m_lvDetails.EndUpdate();
        }

        private void OnItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            if (e.Item == null) return;

            var item = e.Item.Tag as ProtonDriveItem;

            if (item != null)
                m_txtFilename.Text = item.Name;
        }

        private async void OnItemDoubleClick(object sender, EventArgs e)
        {
            if (m_lvDetails.FocusedItem == null) return;

            var item = m_lvDetails.FocusedItem.Tag as ProtonDriveItem;
            if (item == null) return;

            switch (item.Type)
            {
                case StorageProviderItemType.Folder:
                    if (m_lvDetails.FocusedItem.Text == @"..")
                    {
                        PopFolder();
                        m_txtFilename.Text = "";
                        m_selectedItem = m_stack.Pop();
                    }
                    else
                    {
                        m_stack.Push(m_selectedItem);
                        PushFolder(item.Name);
                        m_txtFilename.Text = "";
                        m_selectedItem = await _storageService._storageProvider.GetChildrenForItem(item);
                    }
                    await UpdateListView();
                    break;
                case StorageProviderItemType.File:
                    this.DialogResult = DialogResult.OK;
                    this.Close();
                    break;
            }
        }

        private async void OnFilterChanged(object sender, EventArgs e)
        {
            await UpdateListView();
        }

        private string GetFilePath()
        {
            return folderPath + m_txtFilename.Text;
        }

        private void PushFolder(string folder)
        {
            folderPath = folderPath + folder + "/"; 
        }
        private void PopFolder()
        {
            string[] folders = folderPath.Split(new string[]{ "/"}, StringSplitOptions.RemoveEmptyEntries);
            folders[folders.Length - 1] = "";
            folderPath = string.Join("/", folders);
        }

        private string GetIconKey(string filename)
        {
            var extension = Path.GetExtension(filename);

            if (string.IsNullOrEmpty(extension)) return IconDocument;

            return extension.ToLower() == ".kdbx" ? IconDatabase : IconDocument;
        }
    }
}
