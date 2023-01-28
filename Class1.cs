using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Http;
using System.Numerics;

using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass.UI;

using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;

using Newtonsoft.Json;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;
using System.Security.Policy;
using PgpCore;
using System.IO;
using System.Reflection;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X9;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ProgressBar;
using System.Collections;
using Org.BouncyCastle.Crypto.IO;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography;
using Org.BouncyCastle.Utilities.Encoders;
using static BCrypt.Net.BCrypt;
using KeePass.Ecas;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Net;

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
            //IEnumerable<Cookie> responseCookies = cookies.GetCookies(request.RequestUri).Cast<Cookie>();
            //foreach (Cookie cookie in responseCookies)
            //    Console.WriteLine(cookie.Name + ": " + cookie.Value);
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
        private string username { get { return m_txtUsername.Text.Trim(); } }

        TextBox m_txtPassword = new TextBox();
        private string password { get { return m_txtPassword.Text.Trim(); } }

        TextBox m_txt2fa = new TextBox();
        private string twofa { get { return m_txt2fa.Text.Trim(); } }

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            // Load the last state of the 30 entries option
            m_bEntries30 = m_host.CustomConfig.GetBool(OptionEntries30, true);

            // We want a notification when the user tried to save
            // the current database
            m_host.MainWindow.FileSaved += this.OnFileSaved;

            return true; // Initialization successful
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
            Button m_btnTest = new Button();
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

            m_btnTest.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
            m_btnTest.Location = new Point(12, 301);
            m_btnTest.Name = "m_btnTest";
            m_btnTest.Size = new Size(75, 23);
            m_btnTest.TabIndex = 6;
            m_btnTest.Text = "&Test";
            m_btnTest.UseVisualStyleBackColor = true;
            m_btnTest.Click += new EventHandler(this.OnTest);

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
            form1.Controls.Add(m_btnTest);
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

        private async void OnTest(object sender, EventArgs e)
        {
            // Call asynchronous network methods in a try/catch block to handle exceptions.
            try
            {
                CookieContainer cookies = new CookieContainer();
                HttpClientHandler handler = new HttpClientHandler();
                handler.CookieContainer = cookies;
                HttpClient client = new HttpClient(new LoggingHandler(handler));
                Dictionary<string, string> payload = new Dictionary<string, string>();
                payload["Username"] = "david.haven@pm.me";
                string json = JsonConvert.SerializeObject(payload, Formatting.Indented);
                StringContent data = new StringContent(json, Encoding.UTF8, "application/json");
                client.DefaultRequestHeaders.Add("x-pm-appversion", "Other");
                client.DefaultRequestHeaders.Add("User-Agent", "None");
                HttpResponseMessage response = await client.PostAsync("https://api.protonmail.ch/auth/info", data);
                IEnumerable<Cookie> responseCookies = cookies.GetCookies(new Uri("https://api.protonmail.ch/auth/info")).Cast<Cookie>();
                foreach (Cookie cookie in responseCookies)
                    Debug.WriteLine(cookie.Name + ": " + cookie.Value);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                //string responseBody = "{\"Code\": 1000, \"Modulus\": \"-----BEGIN PGP SIGNED MESSAGE-----\\nHash: SHA256\\n\\n67ZJBtn5Tgo6fQhwCHa19MzSBCdReZctJlBKt/o4MOgaEPfSMyfwkW8RO9Gg6q0mnf90QlWB2a4C3iQv/i6qT1W2ZoHRgCERiP3xI+TW7+ObmVkZCsqlGE0uBObnXPFEqKTAbInmjRDYGBofFzUIks0hHjbpwjfkUq/uR/01PONm1VCQVki4bUJTZ6wxmDy96Z1NnbnrwYkwJs6XTnrSM4oXJwVZr2YSbycJwaDZNaXoltq6+44ZP5O6xBU+Y/vmXjd0WvVGuzMohG8JWryEb805k08iP8uoQQy0P6NUZwOzJSiMrPVye1uzLcJwOZOeAb+QfnN79XhZTTh2kPfE8w==\\n-----BEGIN PGP SIGNATURE-----\\nVersion: ProtonMail\\nComment: https://protonmail.com\\n\\nwl4EARYIABAFAlwB1jwJEDUFhcTpUY8mAABHNgEAlLgC6LYQ16GBUAUxyVK4\\nLfO74OsOhjfvWTkxDai8+9wBANA1X/Oe6zuHNP4Td7HCH1U071zle3yg8cCC\\naLEYnbIG\\n=Mfxn\\n-----END PGP SIGNATURE-----\\n\", \"ServerEphemeral\": \"nTKNGGnF0kkr16Ivb5r/wwaXTw39titwOGlrt7+qPY41CRrdJx7qLuoFoZMT5jSyRJUAB5TBuKx7oOxmUmAg96ppEzHQPX92gBd0OHP5FGef9Whd4xpLyh6SytwrAWQjvCW1qXrU8qIagFxeaQIpd8FkY00LF3vim2Cr4esG7pEM1jWzUYqhFIt/KTPx5H232zwcKChOiPtcP6I090eP/Tkjm+xojKV7Cr5Qgp1NzQF3t0mah3P4SgNkFocWMGw7UW1W77KAIg5WwZVBi8eq3kq0zWUJEGThZtDfBuKT43dQY9oo+ARi3bctCdcMwgX8j07R6TOumgkZTBWc/tMIrw==\", \"Version\": 4, \"Salt\": \"WY1ntCu3u9yiLA==\", \"SRPSession\": \"a786b9a69182945aeffb2423404c4887\"}";
                Dictionary<string, string> authInfo = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseBody);
                // Load keys
                string SRP_MODULUS_KEY = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
                int SRP_LEN_BYTES = 256;
                EncryptionKeys encryptionKeys = new EncryptionKeys(SRP_MODULUS_KEY);

                // Verify signed  message
                PGP pgp = new PGP(encryptionKeys);
                bool verified = await pgp.VerifyClearArmoredStringAsync(authInfo["Modulus"]);
                VerificationResult result = await pgp.VerifyAndReadClearArmoredStringAsync(authInfo["Modulus"]);

                //get other info from response
                int version = int.Parse(authInfo["Version"]);
                byte[] server_challenge = Convert.FromBase64String(authInfo["ServerEphemeral"]);
                byte[] salt = Convert.FromBase64String(authInfo["Salt"]);

                //compute N
                byte[] modulus = Convert.FromBase64String(result.ClearText);
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
                byte[] a = new byte[] { 52, 61, 160, 234, 67, 215, 153, 254, 181, 157, 4, 100, 16, 65, 87, 237, 83, 201, 88, 180, 226, 174, 161, 216, 63, 99, 153, 243, 82, 107, 20, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                //rand.NextBytes(a);
                BigInteger aBig = ByteToBigInteger(a);
                BigInteger A = BigInteger.ModPow(gBig, aBig, N);

                //compute u
                byte[] uLowerInputHash = Concat(A.ToByteArray(), server_challenge);
                byte[] u = Digest(uLowerInputHash);
                BigInteger uBig = ByteToBigInteger(u);

                if(version == 4 || version == 3)
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
                    for(int i = 0; i < newSalt.Length; i++)
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
                    string saltFinalString = Encoding.ASCII.GetString(saltFinal);
                    // Hash the user's password
                    string passwordHash = HashPassword("", saltFinalString);
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
                    byte[] mUpperInputHash = Concat(Concat(A.ToByteArray(), server_challenge),K);
                    byte[] M = Digest(mUpperInputHash);
                    BigInteger KBig = ByteToBigInteger(K);
                    // Compute expected server proof
                    byte[] ESPInputHash = Concat(Concat(A.ToByteArray(), M), K);
                    byte[] expectedServerProof = Digest(ESPInputHash);
                    BigInteger expectedServerProofBig = ByteToBigInteger(expectedServerProof);

                    //post auth info to Proton API
                    Dictionary<string, string> SRPAuth = new Dictionary<string, string>();
                    SRPAuth["Username"] = "";
                    SRPAuth["ClientEphemeral"] = Convert.ToBase64String(A.ToByteArray());
                    SRPAuth["ClientProof"] = Convert.ToBase64String(M);
                    SRPAuth["SRPSession"] = authInfo["SRPSession"];
                    string SRPAuthJson = JsonConvert.SerializeObject(SRPAuth);
                    StringContent SRPAuthData = new StringContent(SRPAuthJson, Encoding.UTF8, "application/json");
                    HttpResponseMessage SRPAuthResponse = await client.PostAsync("https://api.protonmail.ch/auth", SRPAuthData);
                    //SRPAuthResponse.EnsureSuccessStatusCode();
                    string SRPAuthResponseBody = await SRPAuthResponse.Content.ReadAsStringAsync();
                    JObject authResultJSON = JObject.Parse(SRPAuthResponseBody);
                    if (!authResultJSON.ContainsKey("ServerProof"))
                    {
                        MessageService.ShowInfo("Invalid password");
                        return;
                    }
                    byte[] actualServerProof = Convert.FromBase64String((string)authResultJSON["ServerProof"]);
                    BigInteger actualServerProofBig = ByteToBigInteger(actualServerProof);
                    if (expectedServerProofBig == actualServerProofBig)
                    {
                        MessageService.ShowInfo("Authenticated");
                        JObject sessionData = new JObject();
                        sessionData["UID"] = new JValue((string)authResultJSON["UID"]);
                        sessionData["AccessToken"] = new JValue((string)authResultJSON["AccessToken"]);
                        sessionData["RefreshToken"] = new JValue((string)authResultJSON["RefreshToken"]);
                        sessionData["PasswordMode"] = new JValue((string)authResultJSON["PasswordMode"]);
                        string[] scope = ((string)authResultJSON["Scope"]).Split(' ');
                        sessionData["Scope"] = new JArray(scope);

                        client.DefaultRequestHeaders.Add("x-pm-uid", (string)authResultJSON["UID"]);
                        client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)authResultJSON["AccessToken"]);

                        if(((string)authResultJSON["Scope"]).Split(' ').Contains("twofactor"))
                        {
                            string twoFactor = this.twofa;
                            Dictionary<string, string> twoFAAuth = new Dictionary<string, string>();
                            twoFAAuth["TwoFactorCode"] = twoFactor;
                            string twoFAAuthJson = JsonConvert.SerializeObject(twoFAAuth, Formatting.Indented);
                            StringContent twoFAAuthData = new StringContent(twoFAAuthJson, Encoding.UTF8, "application/json");
                            HttpResponseMessage twoFAAuthResponse = await client.PostAsync("https://api.protonmail.ch/auth/2fa", twoFAAuthData);
                            //twoFAAuthResponse.EnsureSuccessStatusCode();
                            string twoFAAuthResponseBody = await twoFAAuthResponse.Content.ReadAsStringAsync();
                            JObject twoFAAuthResultJSON = JObject.Parse(twoFAAuthResponseBody);
                            sessionData["Scope"] = (string)twoFAAuthResultJSON["Scope"];
                            MessageService.ShowInfo(sessionData);
                            HttpResponseMessage userInfoResponse = await client.GetAsync("https://api.protonmail.ch/drive/shares?ShowAll=1");
                            //userInfoResponse.EnsureSuccessStatusCode();
                            string userInfoResponseBody = await userInfoResponse.Content.ReadAsStringAsync();
                            JObject userInfoResponseJSON = JObject.Parse(userInfoResponseBody);
                        }
                    }


                    MessageService.ShowInfo("ok");
                }

            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
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
