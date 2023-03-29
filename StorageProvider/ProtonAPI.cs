using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

using KeePassLib.Utility;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using static BCrypt.Net.BCrypt;

using PgpCore;

using ProtonSecrets.Configuration;

namespace ProtonSecrets.StorageProvider {

    public class ProtonAPI {

        private HttpClient client;

        public ProtonAPI(){
            this.client = new HttpClient();
            this.client.DefaultRequestHeaders.Add("x-pm-appversion", "Other");
            this.client.DefaultRequestHeaders.Add("User-Agent", "None");
        }
        public void addAuthHeaders(string UID, string accessToken)
        {
            this.client.DefaultRequestHeaders.Remove("x-pm-uid");
            this.client.DefaultRequestHeaders.Add("x-pm-uid", UID);
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);
        }
        private async Task<JObject> ProtonRequest(string method, string url, StringContent data = null)
        {
            if (method == "POST")
            {
                try
                {
                    HttpResponseMessage response = await this.client.PostAsync(url, data);
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
                    HttpResponseMessage response = await this.client.GetAsync(url);
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

        private async Task<string> computeKeyPassword(string password)
        {
            //Get user info
            JObject userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            JArray userKeys = (JArray)userInfo["User"]["Keys"];
            string userKeyID = "";
            for (int i = 0; i < userKeys.Count(); i++)
            {
                if ((int)userKeys[i]["Primary"] == 1)
                {
                    userKeyID = (string)userKeys[i]["ID"];
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
            string keySalt_bcrypt = new string(Util.EncodeBase64(keySalt_byte, 16));
            string finalSalt = "$2y$10$" + keySalt_bcrypt;
            string passwordHash = HashPassword(password, finalSalt);
            return passwordHash.Substring(29);
        }

        //logs the user in and returns the corresponding account configuration
        public async Task<AccountConfiguration> Login(string username, string password, string twofa)
        {
            Dictionary<string, string> authPayload = new Dictionary<string, string>();
            authPayload["Username"] = username;
            string json = JsonConvert.SerializeObject(authPayload, Formatting.Indented);
            StringContent data = new StringContent(json, Encoding.UTF8, "application/json");
            JObject authInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/info", data);
            EncryptionKeys encryptionKeys = new EncryptionKeys(Util.SRP_MODULUS_KEY);
            // Verify signed  message
            PGP pgp = new PGP(encryptionKeys);
            bool verified = await pgp.VerifyClearArmoredStringAsync((string)authInfo["Modulus"]);
            VerificationResult result = await pgp.VerifyAndReadClearArmoredStringAsync((string)authInfo["Modulus"]);
            //get other info from response
            int version = int.Parse((string)authInfo["Version"]);
            byte[] server_challenge = Convert.FromBase64String((string)authInfo["ServerEphemeral"]);
            byte[] salt = Convert.FromBase64String((string)authInfo["Salt"]);
            //Compute the SRP proof
            SRP srpRes = Util.SRPCheck(result.ClearText, server_challenge, version, salt, username, password, (string)authInfo["SRPSession"]);
            if (srpRes == null)
            {
                MessageService.ShowInfo("failed SRP authentication");
                return null;
            }
            //Validate SRP proof against the server
            Dictionary<string, string> SRPAuth = new Dictionary<string, string>();
            SRPAuth["Username"] = username;
            SRPAuth["ClientEphemeral"] = srpRes.ClientEphemeral;
            SRPAuth["ClientProof"] = srpRes.ClientProof;
            SRPAuth["SRPSession"] = (string)authInfo["SRPSession"];
            string SRPAuthJson = JsonConvert.SerializeObject(SRPAuth);
            StringContent SRPAuthData = new StringContent(SRPAuthJson, Encoding.UTF8, "application/json");
            JObject srpResult = await ProtonRequest("POST", "https://api.protonmail.ch/auth", SRPAuthData);
            if (srpResult != null && !srpResult.ContainsKey("ServerProof"))
            {
                MessageService.ShowInfo("failed SRP authentication");
                return null;
            }
            else if (srpResult == null)
            {
                MessageService.ShowInfo("failed SRP authentication");
                return null;
            }
            byte[] actualServerProof = Convert.FromBase64String((string)srpResult["ServerProof"]);
            BigInteger actualServerProofBig = Util.ByteToBigInteger(actualServerProof);
            if (Util.ByteToBigInteger(srpRes.expectedServerProof) == actualServerProofBig)
            {
                MessageService.ShowInfo("Authenticated");
            }
            //add headers for later requests
            this.client.DefaultRequestHeaders.Remove("x-pm-uid");
            this.client.DefaultRequestHeaders.Add("x-pm-uid", (string)srpResult["UID"]);
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)srpResult["AccessToken"]);
            //validate 2fa if enabled
            if (((string)srpResult["Scope"]).Split(' ').Contains("twofactor"))
            {
                Dictionary<string, string> twoFAAuth = new Dictionary<string, string>();
                twoFAAuth["TwoFactorCode"] = twofa;
                string twoFAAuthJson = JsonConvert.SerializeObject(twoFAAuth, Formatting.Indented);
                StringContent twoFAAuthData = new StringContent(twoFAAuthJson, Encoding.UTF8, "application/json");
                JObject twoFAAuthInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/2fa", twoFAAuthData);
                //sessionData["Scope"] = (string)twoFAAuthInfo["Scope"];
            }
            string KeyPassword = await computeKeyPassword(password);
            return new AccountConfiguration(KeyPassword, username, (string)srpResult["UID"], (string)srpResult["AccessToken"]);
        }

        public async Task<Stream> DownloadHelper(JToken linkData, PGP nodeKeys, string shareID)
        {
            //decrypt the link private key
            string linkPrivateKey = (string)linkData["NodeKey"];
            string linkPassphrase = (string)linkData["NodePassphrase"];
            string decryptedLinkPassphrase = await nodeKeys.DecryptArmoredStringAsync(linkPassphrase);
            EncryptionKeys decryptedLinkKeys = new EncryptionKeys(linkPrivateKey, decryptedLinkPassphrase);
            PGP decryptedLinkKeys_pgp = new PGP(decryptedLinkKeys);
            //decode block session key
            string contentKeyPacket = (string)linkData["FileProperties"]["ContentKeyPacket"];
            byte[] contentKeyPacket_byte = Convert.FromBase64String(contentKeyPacket);
            // fetch info for specific revision
            string targetLinkId = (string)linkData["LinkID"];
            string linkRevisionId = (string)linkData["FileProperties"]["ActiveRevision"]["ID"];
            JObject linkRevisionInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareID + "/files/" + targetLinkId + "/revisions/" + linkRevisionId);
            JArray blocks = (JArray)linkRevisionInfo["Revision"]["Blocks"];
            byte[] keepassDB_bytes = new byte[] { };
            for (int i = 0; i < blocks.Count(); i++)
            {
                string revisionBlockURL = (string)blocks[i]["URL"];
                // fetch and decrypt unique block
                HttpResponseMessage blockResponse = await client.GetAsync(revisionBlockURL);
                Stream encData = await blockResponse.Content.ReadAsStreamAsync();
                byte[] block;
                using (var memoryStream = new MemoryStream())
                {
                    encData.CopyTo(memoryStream);
                    block = memoryStream.ToArray();
                }
                MemoryStream outputStream = new MemoryStream();
                await decryptedLinkKeys_pgp.DecryptStreamAsync(new MemoryStream(Util.Concat(contentKeyPacket_byte, block)), outputStream);
                //write this portion of the stream to our overall stream
                keepassDB_bytes = Util.Concat(keepassDB_bytes, outputStream.ToArray());
            }
            return new MemoryStream(keepassDB_bytes);
        }
        public async Task<Stream> Download(string path, string email, string keyPassword)
        {
            //Get user info
            JObject userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            JArray userKeys = (JArray)userInfo["User"]["Keys"];
            string userPrivateKey = "";
            for (int i = 0; i < userKeys.Count(); i++)
            {
                if ((int)userKeys[i]["Primary"] == 1)
                {
                    userPrivateKey = (string)userKeys[i]["PrivateKey"];
                }
            }
            //Get address info
            JObject addressInfo = await ProtonRequest("GET", "https://api.protonmail.ch/addresses");
            JArray addresses = (JArray)addressInfo["Addresses"];
            JArray keys = null;
            for (int i = 0; i < addresses.Count(); i++)
            {
                if ((string)addresses[i]["Email"] == email)
                {
                    keys = (JArray)addresses[i]["Keys"];
                }
            }
            string addressPrivateKey = "";
            string addressToken = "";
            for (int i = 0; i < keys.Count(); i++)
            {
                if ((int)keys[i]["Primary"] == 1)
                {
                    addressPrivateKey = (string)keys[i]["PrivateKey"];
                    addressToken = (string)keys[i]["Token"];
                }
            }
            EncryptionKeys encryptionKeys = new EncryptionKeys(userPrivateKey, keyPassword);
            PGP userPrivateKey_pgp = new PGP(encryptionKeys);
            //Decrypt addressToken
            string decryptedToken = await userPrivateKey_pgp.DecryptArmoredStringAsync(addressToken);

            EncryptionKeys adddressKeys = new EncryptionKeys(addressPrivateKey, decryptedToken);
            PGP addressKeys_pgp = new PGP(adddressKeys);

            JObject sharesInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares");
            JArray shares = (JArray)sharesInfo["Shares"];
            string shareID = "";
            string linkID = "";
            for (int i = 0; i < shares.Count(); i++)
            {
                if (shares[i]["CreationTime"].ToString() == "")
                {
                    shareID = (string)shares[i]["ShareID"];
                    linkID = (string)shares[i]["LinkID"];
                }
            }
            JObject shareInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareID);
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];
            //Decrypt sharePassphrase
            string decryptedPassphrase = await addressKeys_pgp.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            PGP shareKeys_pgp = new PGP(shareKeys);

            JObject linkInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareID + "/links/" + linkID);
            string rootLinkName = (string)linkInfo["Link"]["Name"];
            string rootNodePrivateKey = (string)linkInfo["Link"]["NodeKey"];
            string rootNodePassphrase = (string)linkInfo["Link"]["NodePassphrase"];
            //Decrypt linkName
            string decryptedRootLinkName = await shareKeys_pgp.DecryptArmoredStringAsync(rootLinkName);
            //Decrypt root nodePassphrase
            string decryptedRootNodePassphrase = await shareKeys_pgp.DecryptArmoredStringAsync(rootNodePassphrase);
            EncryptionKeys nodeKeys = new EncryptionKeys(rootNodePrivateKey, decryptedRootNodePassphrase);
            PGP nodeKeys_pgp = new PGP(nodeKeys);
            //Get children of root folder
            JObject folderChildrenLinksInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareID + "/folders/" + linkID + "/children");
            // loop through links until we find one with filename == path
            int imageLinkIndex = 0;
            for (int i = 0; i < folderChildrenLinksInfo["Links"].Count(); i++)
            {
                string linkName = (string)folderChildrenLinksInfo["Links"][i]["Name"];
                string nodePrivateKey = (string)folderChildrenLinksInfo["Links"][i]["NodeKey"];
                string nodePassphrase = (string)folderChildrenLinksInfo["Links"][i]["NodePassphrase"];
                //decrypt node passphrase
                string decryptedNodePassphrase = await nodeKeys_pgp.DecryptArmoredStringAsync(nodePassphrase);
                EncryptionKeys subNodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
                PGP subNodeKeys_pgp = new PGP(subNodeKeys);
                //Decrypt filename
                string decryptedLinkName = await nodeKeys_pgp.DecryptArmoredStringAsync(linkName);
                if (decryptedLinkName == path)
                {
                    imageLinkIndex = i;
                }
            }
            return await DownloadHelper(folderChildrenLinksInfo["Links"][imageLinkIndex], nodeKeys_pgp, shareID);
        }

    }
}