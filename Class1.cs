using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Net.Http;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Net;
using System.Data.SqlTypes;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ProgressBar;
using System.Collections;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;
using System.Security.Policy;

using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass.UI;
using KeePass.App.Configuration;

using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;
using KeePass.Ecas;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities;
using static BCrypt.Net.BCrypt;
using PgpCore;
using System.Collections.Specialized;

namespace ProtonSecrets
{
    public class LoggingHandler : DelegatingHandler
    {
        public LoggingHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Debug.WriteLine("Request:");
            Debug.WriteLine(request.ToString());
            if (request.Content != null)
            {
                Debug.WriteLine(await request.Content.ReadAsStringAsync());
            }
            Debug.WriteLine("");

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

            Debug.WriteLine("Response:");
            Debug.WriteLine(response.ToString());
            Debug.WriteLine("cookies:");
            if (response.Content != null)
            {
                Debug.WriteLine(await response.Content.ReadAsStringAsync());
            }
            Debug.WriteLine("");

            return response;
        }
    }
    public sealed class ProtonSecretsExt : Plugin
    {
        // The plugin remembers its host in this variable
        private IPluginHost m_host = null;

        // State of the option to add 30 entries instead of 10
        private bool m_bEntries30 = true;

        // Name of the configuration option to add 30 entries
        // instead of 10
        private const string OptionEntries30 = "SamplePlugin_Entries30";

        TextBox m_txtUsername = new TextBox();
        private string USERNAME { get { return m_txtUsername.Text.Trim(); } }

        TextBox m_txtPassword = new TextBox();
        private string PASSWORD { get { return m_txtPassword.Text.Trim(); } }

        TextBox m_txt2fa = new TextBox();
        private string TWOFA { get { return m_txt2fa.Text.Trim(); } }

        private HttpClient client;

        private string SRP_MODULUS_KEY = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

                xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
                L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
                BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
                MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD / V6NglBd96lZKBmInSXX / kXat
                Sv + y0io + LR8i2 + jV + AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9 + KfE
                kSIgcBRE3WuXC4oj5a2 / U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
                hcTpUY8mAhsMAAD / XQD8DxNI6E78meodQI + wLsrKLeHn32iLvUqJbVDhfWSU
                WO4BAMcm1u02t4VKw++ttECPt + HUgPUq5pqQWe5Q2cW4TMsE
                = Y4Mw
                ---- - END PGP PUBLIC KEY BLOCK-----";
        private int SRP_LEN_BYTES = 256;
        private string email = "";
        private string keyPassword = "";

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            // Load the last state of the 30 entries option
            m_bEntries30 = m_host.CustomConfig.GetBool(OptionEntries30, true);

            // We want a notification when the user tried to save
            // the current database
            m_host.MainWindow.FileSaved += this.OnFileSaved;

            CookieContainer cookies = new CookieContainer();
            HttpClientHandler handler = new HttpClientHandler();
            handler.CookieContainer = cookies;
            client = new HttpClient(new LoggingHandler(handler));
            client.DefaultRequestHeaders.Add("x-pm-appversion", "Other");
            client.DefaultRequestHeaders.Add("User-Agent", "None");
            LoadSessionFromLocalSecureStore();
            return true; // Initialization successful
        }

        private void SaveSessionToLocalSecureStore(JObject sessionData)
        {
            var path = ConfigurationInfo();
            var filename = Path.Combine(path, "session.json");

            var configString = JsonConvert.SerializeObject(sessionData);

            File.WriteAllText(filename, configString);
        }

        private void LoadSessionFromLocalSecureStore()
        {
            var path = ConfigurationInfo();
            var filename = Path.Combine(path, "session.json");
            if (!File.Exists(filename))
                return;
            var configString = File.ReadAllText(filename);
            if (string.IsNullOrEmpty(configString)) return;
            JObject bodyData = JObject.Parse(configString);
            client.DefaultRequestHeaders.Add("x-pm-uid", (string)bodyData["UID"]);
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)bodyData["AccessToken"]);
            this.keyPassword = (string)bodyData["KeyPassword"];
            this.email = (string)bodyData["Email"];
            return;
        }

        private string ConfigurationInfo()
        {
            var isGlobalConfig = !KeePass.Program.Config.Meta.PreferUserConfiguration;
            var asm = Assembly.GetEntryAssembly();
            var filename = asm.Location;
            var directory = Path.GetDirectoryName(filename);

            bool _isPortable = isGlobalConfig
                && !directory.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles))
                && !directory.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

            if (_isPortable)
            {
                return directory;
            }
            else
            {
                return AppConfigSerializer.AppDataDirectory;
            }
        }

        public override void Terminate()
        {
            // Save the state of the 30 entries option
            m_host.CustomConfig.SetBool(OptionEntries30, m_bEntries30);

            // Remove event handler (important!)
            m_host.MainWindow.FileSaved -= this.OnFileSaved;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            // Our menu item below is intended for the main location(s),
            // not for other locations like the group or entry menus
            if (t != PluginMenuType.Main) return null;

            ToolStripMenuItem tsmi = new ToolStripMenuItem("SamplePlugin");

            // Add menu item 'Add Some Groups'
            ToolStripMenuItem tsmiAddGroups = new ToolStripMenuItem();
            tsmiAddGroups.Text = "Add Some Groups";
            tsmiAddGroups.Click += this.OnMenuAddGroups;
            tsmi.DropDownItems.Add(tsmiAddGroups);

            // Add menu item 'Add Some Entries'
            ToolStripMenuItem tsmiAddEntries = new ToolStripMenuItem();
            tsmiAddEntries.Text = "Add Some Entries";
            tsmiAddEntries.Click += this.OnMenuAddEntries;
            tsmi.DropDownItems.Add(tsmiAddEntries);

            tsmi.DropDownItems.Add(new ToolStripSeparator());

            ToolStripMenuItem tsmiEntries30 = new ToolStripMenuItem();
            tsmiEntries30.Text = "Add 30 Entries Instead Of 10";
            tsmiEntries30.Click += this.OnMenuEntries30;
            tsmi.DropDownItems.Add(tsmiEntries30);

            // By using an anonymous method as event handler, we do not
            // need to remember menu item references manually, and
            // multiple calls of the GetMenuItem method (to show the
            // menu item in multiple places) are no problem
            tsmi.DropDownOpening += delegate (object sender, EventArgs e)
            {
                // Disable the commands 'Add Some Groups' and
                // 'Add Some Entries' when the database is not open
                PwDatabase pd = m_host.Database;
                bool bOpen = ((pd != null) && pd.IsOpen);
                tsmiAddGroups.Enabled = bOpen;
                tsmiAddEntries.Enabled = bOpen;

                // Update the checkmark of the menu item
                UIUtil.SetChecked(tsmiEntries30, m_bEntries30);
            };

            return tsmi;
        }

        private void OnMenuAddGroups(object sender, EventArgs e)
        {
            PwDatabase pd = m_host.Database;
            if ((pd == null) || !pd.IsOpen) { Debug.Assert(false); return; }

            PwGroup pgParent = pd.RootGroup;
            Random rnd = new Random();

            for (int i = 0; i < 5; ++i)
            {
                // Add a new group with a random icon
                PwGroup pg = new PwGroup(true, true, "Sample Group #" + i.ToString(),
                    (PwIcon)rnd.Next(0, (int)PwIcon.Count));
                pgParent.AddGroup(pg, true);
            }

            m_host.MainWindow.UpdateUI(false, null, true, null, false, null, true);
        }

        private void OnMenuAddEntries(object sender, EventArgs e)
        {
            // Create a new instance of the form.
            Form form1 = new Form();

            Label m_lblUsername = new Label();
            Label m_lblPassword = new Label();
            Button m_btnLogin = new Button();
            Button m_btnDecrypt = new Button();
            Label m_lbl2fa = new Label();

            m_lblUsername.AutoSize = true;
            m_lblUsername.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            m_lblUsername.Location = new Point(6, 22);
            m_lblUsername.Name = "m_lblUsername";
            m_lblUsername.Size = new Size(73, 13);
            m_lblUsername.TabIndex = 0;
            m_lblUsername.Text = "Username";

            m_txtUsername.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            m_txtUsername.Location = new Point(158, 19);
            m_txtUsername.Name = "m_txtUsername";
            m_txtUsername.Size = new Size(265, 20);
            m_txtUsername.TabIndex = 1;

            m_lblPassword.AutoSize = true;
            m_lblPassword.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            m_lblPassword.Location = new Point(6, 48);
            m_lblPassword.Name = "m_lblPassword";
            m_lblPassword.Size = new Size(69, 13);
            m_lblPassword.TabIndex = 2;
            m_lblPassword.Text = "Password";

            m_txtPassword.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            m_txtPassword.Location = new Point(158, 45);
            m_txtPassword.Name = "m_txtPassword";
            m_txtPassword.Size = new Size(265, 20);
            m_txtPassword.TabIndex = 3;

            m_lbl2fa.AutoSize = true;
            m_lbl2fa.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            m_lbl2fa.Location = new Point(6, 74);
            m_lbl2fa.Name = "m_lbl2fa";
            m_lbl2fa.Size = new Size(69, 13);
            m_lbl2fa.TabIndex = 4;
            m_lbl2fa.Text = "2fa";

            m_txt2fa.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            m_txt2fa.Location = new Point(158, 71);
            m_txt2fa.Name = "m_txt2fa";
            m_txt2fa.Size = new Size(265, 20);
            m_txt2fa.TabIndex = 5;

            m_btnLogin.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
            m_btnLogin.Location = new Point(12, 301);
            m_btnLogin.Name = "m_btnLogin";
            m_btnLogin.Size = new Size(75, 23);
            m_btnLogin.TabIndex = 6;
            m_btnLogin.Text = "Login";
            m_btnLogin.UseVisualStyleBackColor = true;
            m_btnLogin.Click += new EventHandler(this.OnLogin);

            m_btnDecrypt.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Right)));
            m_btnDecrypt.Location = new Point(87, 301);
            m_btnDecrypt.Name = "m_btnDecrypt";
            m_btnDecrypt.Size = new Size(75, 23);
            m_btnDecrypt.TabIndex = 6;
            m_btnDecrypt.Text = "Decrypt";
            m_btnDecrypt.UseVisualStyleBackColor = true;
            m_btnDecrypt.Click += new EventHandler(this.OnDecrypt);

            GroupBox m_grpCredentials = new GroupBox();
            m_grpCredentials.SuspendLayout();
            form1.SuspendLayout();

            m_grpCredentials.Anchor = ((AnchorStyles)(((AnchorStyles.Top | AnchorStyles.Left) | AnchorStyles.Right)));
            m_grpCredentials.Controls.Add(m_lblUsername);
            m_grpCredentials.Controls.Add(m_txtUsername);
            m_grpCredentials.Controls.Add(m_lblPassword);
            m_grpCredentials.Controls.Add(m_txtPassword);
            m_grpCredentials.Controls.Add(m_lbl2fa);
            m_grpCredentials.Controls.Add(m_txt2fa);
            form1.Controls.Add(m_btnLogin);
            form1.Controls.Add(m_btnDecrypt);
            m_grpCredentials.Font = new Font("Microsoft Sans Serif", 8.25F, FontStyle.Bold, GraphicsUnit.Point, ((byte)(0)));
            m_grpCredentials.Location = new Point(12, 66);
            m_grpCredentials.Name = "m_grpCredentials";
            m_grpCredentials.Size = new Size(429, 100);
            m_grpCredentials.TabIndex = 19;
            m_grpCredentials.TabStop = false;
            m_grpCredentials.Text = "Credentials";

            form1.Controls.Add(m_grpCredentials);
            form1.AutoScaleDimensions = new SizeF(6F, 13F);
            form1.AutoScaleMode = AutoScaleMode.Font;
            form1.ClientSize = new Size(600, 336);
            form1.FormBorderStyle = FormBorderStyle.FixedDialog;
            form1.MaximizeBox = false;
            form1.MinimizeBox = false;
            form1.Name = "Proton Account";
            form1.StartPosition = FormStartPosition.CenterParent;
            form1.Text = "Authenticate with your Proton account";
            m_grpCredentials.ResumeLayout(false);
            m_grpCredentials.PerformLayout();
            form1.ResumeLayout(false);
            // Display the form as a modal dialog box.
            form1.ShowDialog();
        }

        /*
         * return a new byte of length start.length + end.length
         * whose element are the elements of start followed by the elements of end
         * */
        private byte[] Concat(byte[] start, byte[] end)
        {
            byte[] concatenatedByte = new byte[start.Length+end.Length];
            Array.Copy(start, 0, concatenatedByte, 0, start.Length);
            Array.Copy(end, 0, concatenatedByte, start.Length, end.Length);
            return concatenatedByte;
        }

        /*
         * Convert a byte array to BigInteger. We need to specify the sign of the byte array by
         * appending the byte 0. See https://stackoverflow.com/questions/22053462/microsoft-biginteger-goes-negative-when-i-import-from-an-array
         * */
        private BigInteger ByteToBigInteger(byte[] input)
        {

            Array.Resize(ref input, input.Length + 1);
            input[input.Length - 1] = 0;
            BigInteger output = new BigInteger(input);
            return output;
        }

        /*
         * Hash the input byte array by applying the sha512 algorithm
         */
        private byte[] Digest(byte[] input)
        {
            byte[] input0 = Concat(input, new Byte[] { Convert.ToByte(0) });
            byte[] input1 = Concat(input, new Byte[] { Convert.ToByte(1) });
            byte[] input2 = Concat(input, new Byte[] { Convert.ToByte(2) });
            byte[] input3 = Concat(input, new Byte[] { Convert.ToByte(3) });
            SHA512 sha = new SHA512Managed();
            byte[] shaOutpu1 = sha.ComputeHash(input0);
            byte[] shaOutpu2 = sha.ComputeHash(input1);
            byte[] shaOutpu3 = sha.ComputeHash(input2);
            byte[] shaOutpu4 = sha.ComputeHash(input3);
            return Concat(Concat(shaOutpu1, shaOutpu2), Concat(shaOutpu3, shaOutpu4));
        }

        private byte[] TakeSuffix(byte[] array, int n)
        {
            byte[] answer = new byte[n];
            int j = 0;
            for(int i = 0; i < array.Length; i++)
            {
                int relativePosition = array.Length - i;
                if(relativePosition <= n)
                {
                    answer[j] = array[i];
                    j += 1;
                }
            }
            return answer;
        }

        private byte[] TakePrefix(byte[] array, int n)
        {
            byte[] answer = new byte[n];
            for (int i = 0; i < array.Length; i++)
            {
                if (i < n)
                {
                    answer[i] = array[i];
                }
            }
            return answer;
        }

        /// <summary>
        ///  Encode a byte array using BCrypt's slightly-modified base64 encoding scheme. Note that this
        ///  is *not* compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
        ///                                     illegal values.</exception>
        /// <param name="byteArray">The byte array to encode.</param>
        /// <param name="length">   The number of bytes to encode.</param>
        /// <returns>Base64-encoded string.</returns>
        private char[] EncodeBase64(byte[] byteArray, int length)
        {
            // Table for Base64 encoding
            char[] Base64Code = {
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
            };
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
            char[] encoded = new char[encodedSize];

            int pos = 0;
            int off = 0;
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }

            return encoded;
        }

        private async Task<JObject> ProtonRequest(string method, string url, StringContent data = null)
        {
            if(method == "POST")
            {
                try
                {
                    HttpResponseMessage response = await client.PostAsync(url, data);
                    //response.EnsureSuccessStatusCode();
                    string responseBody = await response.Content.ReadAsStringAsync();
                    JObject bodyData = JObject.Parse(responseBody);
                    return bodyData;
                }
                catch (HttpRequestException exception)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", exception.Message);
                    MessageService.ShowInfo(exception.Message);
                    return null;
                }
            }
            else
            {
                try
                {
                    HttpResponseMessage response = await client.GetAsync(url);
                    //response.EnsureSuccessStatusCode();
                    string responseBody = await response.Content.ReadAsStringAsync();
                    JObject bodyData = JObject.Parse(responseBody); ;
                    return bodyData;
                }
                catch (HttpRequestException exception)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", exception.Message);
                    MessageService.ShowInfo(exception.Message);
                    return null;
                }
            }
        }

        private string ProtonSalt(byte[] salt)
        {
            //Compute the salt for the password hash
            byte[] protonBytes = Encoding.ASCII.GetBytes("proton");
            byte[] sShort = TakeSuffix(Concat(salt, protonBytes), 16);
            string s = Convert.ToBase64String(sShort);
            byte[] newSalt = Encoding.ASCII.GetBytes(s);
            byte[] bcrypt_base64 = Encoding.ASCII.GetBytes("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            byte[] std_base64chars = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
            Dictionary<byte, byte> translation = new Dictionary<byte, byte>();
            for (int i = 0; i < std_base64chars.Length; i++)
            {
                byte nextByte = std_base64chars[i];
                translation[nextByte] = bcrypt_base64[i];
            }
            byte[] newSalt2 = new byte[newSalt.Length];
            for (int i = 0; i < newSalt.Length; i++)
            {
                if (translation.ContainsKey(newSalt[i]))
                {
                    newSalt2[i] = translation[newSalt[i]];
                }
                else
                {
                    newSalt2[i] = newSalt[i];
                }
            }
            byte[] saltPrefix = Encoding.ASCII.GetBytes("$2y$10$");
            byte[] saltFinal = Concat(saltPrefix, newSalt2);
            return Encoding.ASCII.GetString(saltFinal);
        }
        private async Task<JObject> SRPCheck(string base64Modulus, byte[] server_challenge, int version, byte[] salt,string username, string password, string srpSession)
        {
            //compute N
            byte[] modulus = Convert.FromBase64String(base64Modulus);
            BigInteger N = ByteToBigInteger(modulus);
            //compute g
            byte[] g = new byte[SRP_LEN_BYTES];
            g[0] = 2;
            BigInteger gBig = ByteToBigInteger(g);
            //compute k
            byte[] kLowerInputHash = Concat(g, modulus);
            byte[] k = Digest(kLowerInputHash);
            BigInteger kBig = ByteToBigInteger(k);
            //compute a and A
            Random rand = new Random();
            byte[] a = new byte[] { 52, 61, 160, 234, 67, 215, 153, 254, 181, 157, 4, 100, 16, 65, 87, 237, 83, 201, 88, 180, 226, 174, 161, 216, 63, 99, 153, 243, 82, 107, 20, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            //rand.NextBytes(a);
            BigInteger aBig = ByteToBigInteger(a);
            BigInteger A = BigInteger.ModPow(gBig, aBig, N);
            //compute u
            byte[] uLowerInputHash = Concat(A.ToByteArray(), server_challenge);
            byte[] u = Digest(uLowerInputHash);
            BigInteger uBig = ByteToBigInteger(u);
            if (version != 4 && version != 3)
            {
                return null;
            }
            // Hash the user's password
            string customSalt = ProtonSalt(salt);
            string passwordHash = HashPassword(password, customSalt);
            byte[] hashedPwdByte = Encoding.ASCII.GetBytes(passwordHash);
            // Compute x (private key)
            byte[] xLowerInputHash = Concat(hashedPwdByte, modulus);
            byte[] x = Digest(xLowerInputHash);
            BigInteger xBig = ByteToBigInteger(x);
            // Compute v
            BigInteger vBig = BigInteger.ModPow(gBig, xBig, N);
            // Compute S (K)
            BigInteger BBig = ByteToBigInteger(server_challenge);
            BigInteger sValue = BBig - (kBig * vBig);
            BigInteger sExponent = aBig + (uBig * xBig);
            BigInteger SBig = BigInteger.ModPow(sValue, sExponent, N);
            if (sValue.Sign == -1) // see https://stackoverflow.com/questions/74664517/c-sharp-gives-me-different-result-of-modpow-from-java-python-is-this-a-bug
            {
                SBig += N;
            }
            byte[] K = TakePrefix(SBig.ToByteArray(), SRP_LEN_BYTES);
            // Compute M
            byte[] mUpperInputHash = Concat(Concat(A.ToByteArray(), server_challenge), K);
            byte[] M = Digest(mUpperInputHash);
            BigInteger KBig = ByteToBigInteger(K);
            // Compute expected server proof
            byte[] ESPInputHash = Concat(Concat(A.ToByteArray(), M), K);
            byte[] expectedServerProof = Digest(ESPInputHash);
            BigInteger expectedServerProofBig = ByteToBigInteger(expectedServerProof);
            //post auth info to Proton API
            Dictionary<string, string> SRPAuth = new Dictionary<string, string>();
            SRPAuth["Username"] = username;
            SRPAuth["ClientEphemeral"] = Convert.ToBase64String(A.ToByteArray());
            SRPAuth["ClientProof"] = Convert.ToBase64String(M);
            SRPAuth["SRPSession"] = srpSession;
            string SRPAuthJson = JsonConvert.SerializeObject(SRPAuth);
            StringContent SRPAuthData = new StringContent(SRPAuthJson, Encoding.UTF8, "application/json");
            JObject srpResult = await ProtonRequest("POST", "https://api.protonmail.ch/auth", SRPAuthData);
            if (srpResult != null && !srpResult.ContainsKey("ServerProof"))
            {
                return null;
            }else if(srpResult == null){
                return null;
            }
            byte[] actualServerProof = Convert.FromBase64String((string)srpResult["ServerProof"]);
            BigInteger actualServerProofBig = ByteToBigInteger(actualServerProof);
            if (expectedServerProofBig == actualServerProofBig)
            {
                MessageService.ShowInfo("Authenticated");
                return srpResult;
            }
            return null;
        }
        private async Task<bool> Login(string username, string password)
        {
            Dictionary<string, string> authPayload = new Dictionary<string, string>();
            authPayload["Username"] = username;
            string json = JsonConvert.SerializeObject(authPayload, Formatting.Indented);
            StringContent data = new StringContent(json, Encoding.UTF8, "application/json");
            JObject authInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/info", data);
            EncryptionKeys encryptionKeys = new EncryptionKeys(SRP_MODULUS_KEY);
            // Verify signed  message
            PGP pgp = new PGP(encryptionKeys);
            bool verified = await pgp.VerifyClearArmoredStringAsync((string)authInfo["Modulus"]);
            VerificationResult result = await pgp.VerifyAndReadClearArmoredStringAsync((string)authInfo["Modulus"]);
            //get other info from response
            int version = int.Parse((string)authInfo["Version"]);
            byte[] server_challenge = Convert.FromBase64String((string)authInfo["ServerEphemeral"]);
            byte[] salt = Convert.FromBase64String((string)authInfo["Salt"]);
            //validate SRP authentication
            JObject srpRes = await SRPCheck(result.ClearText, server_challenge, version, salt,username, password, (string)authInfo["SRPSession"]);
            if(srpRes == null)
            {
                MessageService.ShowInfo("failed SRP authentication");
                return false;
            }
            //session object should be stored in file cache
            JObject sessionData = new JObject();
            sessionData["UID"] = new JValue((string)srpRes["UID"]);
            sessionData["AccessToken"] = new JValue((string)srpRes["AccessToken"]);
            sessionData["RefreshToken"] = new JValue((string)srpRes["RefreshToken"]);
            sessionData["PasswordMode"] = new JValue((string)srpRes["PasswordMode"]);
            string[] scope = ((string)srpRes["Scope"]).Split(' ');
            sessionData["Scope"] = new JArray(scope);

            //add headers for later requests
            client.DefaultRequestHeaders.Add("x-pm-uid", (string)srpRes["UID"]);
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)srpRes["AccessToken"]);

            if (((string)srpRes["Scope"]).Split(' ').Contains("twofactor"))
            {
                string twoFactor = this.TWOFA;
                Dictionary<string, string> twoFAAuth = new Dictionary<string, string>();
                twoFAAuth["TwoFactorCode"] = twoFactor;
                string twoFAAuthJson = JsonConvert.SerializeObject(twoFAAuth, Formatting.Indented);
                StringContent twoFAAuthData = new StringContent(twoFAAuthJson, Encoding.UTF8, "application/json");
                JObject twoFAAuthInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/2fa", twoFAAuthData);
                sessionData["Scope"] = (string)twoFAAuthInfo["Scope"];
            }
            sessionData["Email"] = username;
            sessionData["KeyPassword"] = await computeKeyPassword(password);
            SaveSessionToLocalSecureStore(sessionData);
            return true;
        }

        private async Task<string> computeKeyPassword(string password)
        {
            //Get user info
            JObject userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            JArray userKeys = (JArray)userInfo["User"]["Keys"];
            string userKeyID = "";
            string userPrivateKey = "";
            for (int i = 0; i < userKeys.Count(); i++)
            {
                if ((int)userKeys[i]["Primary"] == 1)
                {
                    userKeyID = (string)userKeys[i]["ID"];
                    userPrivateKey = (string)userKeys[i]["PrivateKey"];
                }
            }
            //Get salts info
            JObject saltsInfo = await ProtonRequest("GET", "https://api.protonmail.ch/keys/salts");
            JArray userKeySalt = (JArray)saltsInfo["KeySalts"];
            string keySalt = "";
            for (int i = 0; i < userKeySalt.Count(); i++)
            {
                if ((string)userKeySalt[i]["ID"] == userKeyID)
                {
                    keySalt = (string)userKeySalt[i]["KeySalt"];
                }
            }
            byte[] keySalt_byte = Convert.FromBase64String(keySalt);
            string keySalt_bcrypt = new string(EncodeBase64(keySalt_byte, 16));
            string finalSalt = "$2y$10$" + keySalt_bcrypt;
            string passwordHash = HashPassword(password, finalSalt);
            return passwordHash.Substring(29);
        }
        private async void OnLogin(object sender, EventArgs e)
        {
            string username = USERNAME;
            string password = PASSWORD;
            bool successLogin = await Login(username, password);
            if (!successLogin)
            {
                MessageService.ShowInfo("Failed login step");
                return;
            }

            //EncryptionKeys adddressKeys = new EncryptionKeys(addressPrivateKey, decryptedToken);
            //PGP addressKeys_pgp = new PGP(adddressKeys);
            //string sharePrivateKey = "";
            //string sharePassphrase = "";
            //string sharePassphraseSignature = ""
            //Decrypt share session key
            //string decryptedPassPhrase = await addressKeys_pgp.DecryptArmoredStringAsync(sharePassphrase);

            //string linkName = "";
            //EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassPhrase);
            //PGP shareKeys_pgp = new PGP(shareKeys);
            //Decrypt link name
            //string decryptedLinkName = await shareKeys_pgp.DecryptArmoredStringAsync(linkName);
            //MessageService.ShowInfo(decryptedLinkName);

        }

        private async void OnDecrypt(object sender, EventArgs e)
        {
            //Get user info
            JObject userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            JArray userKeys = (JArray)userInfo["User"]["Keys"];
            string userKeyID = "";
            string userPrivateKey = "";
            for (int i = 0; i < userKeys.Count(); i++)
            {
                if ((int)userKeys[i]["Primary"] == 1)
                {
                    userKeyID = (string)userKeys[i]["ID"];
                    userPrivateKey = (string)userKeys[i]["PrivateKey"];
                }
            }
            //Get address info
            JObject addressInfo = await ProtonRequest("GET", "https://api.protonmail.ch/addresses");
            JArray addresses = (JArray)addressInfo["Addresses"];
            JArray keys = null;
            for (int i = 0; i < addresses.Count(); i++)
            {
                if ((string)addresses[i]["Email"] == this.email)
                {
                    keys = (JArray)addresses[i]["Keys"];
                }
            }
            string addressPrivateKey = "";
            string addressPublicKey = "";
            string addressToken = "";
            for (int i = 0; i < keys.Count(); i++)
            {
                if ((int)keys[i]["Primary"] == 1)
                {
                    addressPrivateKey = (string)keys[i]["PrivateKey"];
                    addressPublicKey = (string)keys[i]["PublicKey"];
                    addressToken = (string)keys[i]["Token"];
                }
            }
            EncryptionKeys encryptionKeys = new EncryptionKeys(userPrivateKey, this.keyPassword);
            PGP userPrivateKey_pgp = new PGP(encryptionKeys);
            //Decrypt addressToken
            string decryptedToken = await userPrivateKey_pgp.DecryptArmoredStringAsync(addressToken);

            EncryptionKeys adddressKeys = new EncryptionKeys(addressPrivateKey, decryptedToken);
            PGP addressKeys_pgp = new PGP(adddressKeys);

        }


        private void OnMenuEntries30(object sender, EventArgs e)
        {
            m_bEntries30 = !m_bEntries30; // Toggle the option

            // The checkmark of the menu item is updated by
            // our DropDownOpening event handler
        }

        private void OnFileSaved(object sender, FileSavedEventArgs e)
        {
            MessageService.ShowInfo("SamplePlugin has been notified that the user tried to save to the following file:",
                e.Database.IOConnectionInfo.Path, "Result: " +
                (e.Success ? "success." : "failed."));
        }
    }
}
