using System;
using System.Windows.Forms;
using System.Threading.Tasks;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib.Utility;
using KeePassLib.Serialization;

using ProtonSecrets.Configuration;
using ProtonSecrets.StorageProvider;
using ProtonSecrets.Forms;

namespace ProtonSecrets
{
    public sealed class ProtonSecretsExt : Plugin
    {

        //new variables
        private ToolStripMenuItem _tsOpenFromProtonDrive;
        private ToolStripMenuItem _tsSaveToCloudDrive;
        private ConfigurationService _configService;
        private IPluginHost _host;
        private StorageService _storageService;
        private KpResources _kpResources;

        public override bool Initialize(IPluginHost pluginHost)
        {
            if (_host != null) Terminate();
            if (pluginHost == null) return false;

            _host = pluginHost;

            //Load the configuration
            _configService = new ConfigurationService();
            _configService.Load();

            //Initialize the Proton provider
            _storageService = new StorageService(new ProtonDriveStorageProvider(_configService));
            _storageService.RegisterPrefixes();

            // Initialize KeePass-Resource Service
            _kpResources = new KpResources(_host);

            // Add "Open from ProtonDrive..." to File\Open menu.
            var fileMenu = _host.MainWindow.MainMenu.Items["m_menuFile"] as ToolStripMenuItem;
            if (fileMenu != null)
            {
                var openMenu = fileMenu.DropDownItems["m_menuFileOpen"] as ToolStripMenuItem;
                if (openMenu != null)
                {
                    _tsOpenFromProtonDrive = new ToolStripMenuItem("Open from ProtonDrive...");
                    _tsOpenFromProtonDrive.Click += OnOpenFromProtonDrive;
                    _tsOpenFromProtonDrive.ShortcutKeys = Keys.Control | Keys.Alt | Keys.O;
                    openMenu.DropDownItems.Add(_tsOpenFromProtonDrive);
                }
                var saveMenu = fileMenu.DropDownItems["m_menuFileSaveAs"] as ToolStripMenuItem;
                if (saveMenu != null)
                {
                    var index = saveMenu.DropDownItems.IndexOfKey("m_menuFileSaveAsSep0");

                    _tsSaveToCloudDrive = new ToolStripMenuItem("Save to Proton Drive...");
                    _tsSaveToCloudDrive.Click += OnSaveToProtonDrive;
                    saveMenu.DropDownItems.Insert(index, _tsSaveToCloudDrive);

                }
            }
            return true; // Initialization successful
        }

        private async void OnShowSetting(object sender, EventArgs e)
        {
            var dlg = new ProtonDriveAccountForm(_storageService._storageProvider._api);
            var result = UIUtil.ShowDialogAndDestroy(dlg);

            if (result == DialogResult.OK && dlg.Account != null)
            {
                _storageService._storageProvider._configService.Account = dlg.Account;
                _storageService._storageProvider._configService.IsLoaded = true;
                await _storageService._storageProvider.Init();
            }
        }

        private async void OnOpenFromProtonDrive(object sender, EventArgs eventArgs)
        {
            // First usage: register new account
            if (!(await HasAccounts())) return;

            var form = new ProtonDriveFilePicker(_storageService, _kpResources, ProtonDriveFilePicker.Mode.Open);
            var result = UIUtil.ShowDialogAndDestroy(form);

            if (result != DialogResult.OK)
                return;

            var ci = IOConnectionInfo.FromPath("proton:///" + form.ResultUri);
            ci.CredSaveMode = IOCredSaveMode.SaveCred;

            _host.MainWindow.OpenDatabase(ci, null, false);
        }

        private async void OnSaveToProtonDrive(object sender, EventArgs eventArgs)
        {
            if (_host.Database == null) return;

            // First usage: register new account
            if (!(await HasAccounts())) return;

            var form = new ProtonDriveFilePicker(_storageService, _kpResources, ProtonDriveFilePicker.Mode.Save);
            var result = UIUtil.ShowDialogAndDestroy(form);

            if (result != DialogResult.OK)
                return;

            var ci = IOConnectionInfo.FromPath("proton:///" + form.ResultUri);
            ci.CredSaveMode = IOCredSaveMode.SaveCred;

            _host.MainWindow.SaveDatabaseAs(_host.Database, ci, true, null, true);
        }

        private async Task<bool> HasAccounts()
        {
            if (_configService.Account != null) return true;

            var result = MessageService.Ask(
                "At least one account is required to work with ProtonPass.\r\nWould you like to open ProtonPass Settings to create a new account?",
                "ProtonPass", MessageBoxButtons.YesNo);

            if (result == DialogResult.Yes)
            {
                if (_storageService == null)
                {
                    _storageService = new StorageService(new ProtonDriveStorageProvider(_configService));
                    _storageService.RegisterPrefixes();
                }
                var dlg = new ProtonDriveAccountForm(_storageService._storageProvider._api);
                var res = UIUtil.ShowDialogAndDestroy(dlg);

                if (res == DialogResult.OK)
                {
                    _storageService._storageProvider._configService.Account = dlg.Account;
                    _storageService._storageProvider._configService.IsLoaded = true;
                    await _storageService._storageProvider.Init();
                }
            }

            return false;
        }

        public override void Terminate()
        {
            if (_host == null) return;

            _configService.Save();
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t == PluginMenuType.Main)
            {
                // Add the menu option for configuration under Tools
                var tsShowSettings = new ToolStripMenuItem("ProtonSecrets Settings...");
                tsShowSettings.Click += OnShowSetting;

                return tsShowSettings;
            }

            return null; // No menu items in other locations
        }
        
    }
}
