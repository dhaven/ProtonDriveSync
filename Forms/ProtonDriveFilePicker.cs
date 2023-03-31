using KeePass.UI;
using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using ProtonSecrets.Configuration;
using ProtonSecrets.StorageProvider;
using System;
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

namespace ProtonSecrets.Forms
{
    public partial class ProtonDriveFilePicker : Form
    {
        public enum Mode
        {
            Unknown,
            Open,
            Save,
        }
        private ConfigurationService m_configService;
        private bool m_isInit;
        private StorageService m_storageService;
        private ProtonDriveStorageProvider m_provider;
        private Mode m_mode;
        private IEnumerable<ProtonDriveItem> m_selectedItem;
        private readonly Stack<IEnumerable<ProtonDriveItem>> m_stack = new Stack<IEnumerable<ProtonDriveItem>>();
        private string folderPath;
        private string filename;

        public string ResultUri
        {
            get
            {
                return GetFilePath();
            }
        }

        public ProtonDriveFilePicker()
        {
            InitializeComponent();
        }

        public async Task InitEx(ConfigurationService configService, StorageService storageService, Mode mode)
        {
            if (configService == null) throw new ArgumentNullException("configService");
            if (storageService == null) throw new ArgumentNullException("storageService");
            if (mode == Mode.Unknown) throw new ArgumentException("mode");

            m_configService = configService;
            m_storageService = storageService;
            m_provider = new ProtonDriveStorageProvider(configService.Account);
            await m_provider.Init();
            m_mode = mode;
            folderPath = "";
        }

        private async void OnFormLoad(object sender, EventArgs e)
        {
            GlobalWindowManager.AddWindow(this);

            m_isInit = true;

            m_lvDetails.Columns.Add("Name");
            m_lvDetails.Columns.Add("Id");
            m_lvDetails.Columns.Add("Type");
            m_lvDetails.Columns.Add("Changed Date");

            UIUtil.ResizeColumns(m_lvDetails, new int[] {
                4, 1, 1, 1 }, true);

            m_isInit = false;

            try
            {
                m_selectedItem = await m_provider.GetRootItem();
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

            ProtonDriveItem dbToOpen = m_selectedItem.SingleOrDefault(_ => _.Name == filename);
            switch (m_mode)
            {
                case Mode.Open:
                    if (dbToOpen == null)
                    {
                        return;
                    }
                    else
                    {
                        switch (dbToOpen.Type)
                        {
                            case StorageProviderItemType.File:
                                DialogResult = DialogResult.OK;
                                break;

                            case StorageProviderItemType.Folder:
                                m_stack.Push(m_selectedItem);
                                PushFolder(dbToOpen.Name);
                                filename = "";
                                m_txtFilename.Text = GetFilePath();
                                m_selectedItem = await m_provider.GetChildrenForItem(dbToOpen);
                                await UpdateListView();
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
                lvi.SubItems.Add(string.Empty);
                lvi.SubItems.Add("Folder");
                lvi.SubItems.Add(string.Empty);
            }
            foreach (var child in m_selectedItem)
            {
                var lvi = m_lvDetails.Items.Add(child.Name);
                lvi.Tag = child;
                lvi.SubItems.Add(child.Id);
                switch (child.Type)
                {
                    case StorageProviderItemType.Folder:
                        lvi.SubItems.Add("Folder");
                        break;
                    case StorageProviderItemType.File:
                        lvi.SubItems.Add("File");
                        break;
                    default:
                        lvi.SubItems.Add("Unknown");
                        break;
                }
            }
            m_lvDetails.EndUpdate();
        }

        private void OnItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            if (e.Item == null) return;

            var item = e.Item.Tag as ProtonDriveItem;

            if (item != null)
                filename = item.Name;
                m_txtFilename.Text = GetFilePath();
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
                        filename = "";
                        m_txtFilename.Text = GetFilePath();
                        m_selectedItem = m_stack.Pop();
                    }
                    else
                    {
                        m_stack.Push(m_selectedItem);
                        PushFolder(item.Name);
                        filename = "";
                        m_txtFilename.Text = GetFilePath();
                        m_selectedItem = await m_provider.GetChildrenForItem(item);
                    }
                    await UpdateListView();
                    break;
                case StorageProviderItemType.File:
                    this.DialogResult = DialogResult.OK;
                    this.Close();
                    break;
            }
        }

        private string GetFilePath()
        {
            return folderPath + filename;
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
    }
}
