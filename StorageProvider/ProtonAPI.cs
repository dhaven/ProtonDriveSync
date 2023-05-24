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
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System.Security.Cryptography;
using static Org.BouncyCastle.Bcpg.OpenPgp.PgpEncryptedDataGenerator;
using System.Drawing;

namespace ProtonSecrets.StorageProvider {

    public class ProtonAPI
    {

        private HttpClient client;
        private string shareId;
        public PGP addressKeys;

        private string addressKeyPassphrase = "7f7**";
        private string parentNodePassphrase = "zGl**";
        private string ParentLinkID = "0vh**";
        private string shareID = "AQ**";
        private string addressID = "Yu**";
        private string decryptedParentNodeHashKey = "C8z**";
        private string myemail = "da**";

        internal class ProtonLink
        {
            public PGP ParentKeys;
            public string LinkID;
            public ProtonLink(PGP parentKey, string linkID)
            {
                ParentKeys = parentKey;
                LinkID = linkID;
            }
        }

        public ProtonAPI()
        {
            this.client = new HttpClient();
            this.client.DefaultRequestHeaders.Add("x-pm-appversion", "Other");
            this.client.DefaultRequestHeaders.Add("User-Agent", "None");
        }
        public void AddAuthHeaders(string UID, string accessToken)
        {
            this.client.DefaultRequestHeaders.Remove("x-pm-uid");
            this.client.DefaultRequestHeaders.Add("x-pm-uid", UID);
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);
        }

        public async Task InitUserKeys(string email, string keyPassword)
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

            EncryptionKeys adddressKeys_enc = new EncryptionKeys(addressPrivateKey, decryptedToken);
            this.addressKeys = new PGP(adddressKeys_enc);

            JObject sharesInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares");
            JArray shares = (JArray)sharesInfo["Shares"];
            for (int i = 0; i < shares.Count(); i++)
            {
                if (shares[i]["CreationTime"].ToString() == "")
                {
                    this.shareId = (string)shares[i]["ShareID"];
                }
            }
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
            else if(method == "PUT")
            {
                try
                {
                    HttpResponseMessage response = await this.client.PutAsync(url, data);
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

        private async Task<string> ComputeKeyPassword(string password)
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
                MessageService.ShowInfo("failed SRP authentication: unable to compute the proof");
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
                MessageService.ShowInfo("failed SRP authentication: missing proof returned by server");
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
            string KeyPassword = await ComputeKeyPassword(password);
            return new AccountConfiguration(KeyPassword, username, (string)srpResult["UID"], (string)srpResult["AccessToken"]);
        }

        public async Task<IEnumerable<ProtonDriveItem>> GetRootChildren()
        {
            JObject shareInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId);
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];
            //Decrypt sharePassphrase
            string decryptedPassphrase = await this.addressKeys.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            PGP shareKeys_pgp = new PGP(shareKeys);
            JObject linkInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId + "/links/" + (string)shareInfo["LinkID"]);
            string rootNodePrivateKey = (string)linkInfo["Link"]["NodeKey"];
            string rootNodePassphrase = (string)linkInfo["Link"]["NodePassphrase"];
            //Decrypt root nodePassphrase
            string decryptedRootNodePassphrase = await shareKeys_pgp.DecryptArmoredStringAsync(rootNodePassphrase);
            EncryptionKeys nodeKeys = new EncryptionKeys(rootNodePrivateKey, decryptedRootNodePassphrase);
            PGP nodeKeys_pgp = new PGP(nodeKeys);
            return await GetChildren(nodeKeys_pgp, (string)shareInfo["LinkID"], this.shareId);
        }
        //returns a list of ProtonDriveItems that are the children of Link Id
        public async Task<IEnumerable<ProtonDriveItem>> GetChildren(PGP parentKeys, string Id, string ShareId)
        {
            List<ProtonDriveItem> children = new List<ProtonDriveItem>();
            JObject childrenLinks = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + ShareId + "/folders/" + Id + "/children");
            for (int i = 0; i < childrenLinks["Links"].Count(); i++)
            {
                string nodePrivateKey = (string)childrenLinks["Links"][i]["NodeKey"];
                string nodePassphrase = (string)childrenLinks["Links"][i]["NodePassphrase"];
                //decrypt node passphrase
                string decryptedNodePassphrase = await parentKeys.DecryptArmoredStringAsync(nodePassphrase);
                EncryptionKeys subNodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
                PGP subNodeKeys_pgp = new PGP(subNodeKeys);
                //Decrypt filename
                string linkName = (string)childrenLinks["Links"][i]["Name"];
                string decryptedLinkName = await parentKeys.DecryptArmoredStringAsync(linkName);
                ProtonDriveItem nextChild = new ProtonDriveItem();
                nextChild.Name = decryptedLinkName;
                nextChild.ParentKeys = subNodeKeys_pgp;
                nextChild.ShareId = ShareId;
                nextChild.Id = (string)childrenLinks["Links"][i]["LinkID"];
                if ((int)childrenLinks["Links"][i]["Size"] != 0)
                {
                    nextChild.Size = Util.ConvertByteUnits((int)childrenLinks["Links"][i]["Size"]);
                }
                nextChild.LastModifiedDateTime = DateTimeOffset.FromUnixTimeSeconds((long)childrenLinks["Links"][i]["ModifyTime"]);
                if ((int)childrenLinks["Links"][i]["Type"] == 1)
                {
                    nextChild.Type = StorageProviderItemType.Folder;
                }
                else
                {
                    nextChild.Type = StorageProviderItemType.File;
                }
                children.Add(nextChild);
            }
            return children;
        }


        public async Task<Stream> Download(string path)
        {
            string[] folders = path.Split(new string[] { "/" }, StringSplitOptions.RemoveEmptyEntries);
            JObject shareInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId);
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];
            //Decrypt sharePassphrase
            string decryptedPassphrase = await this.addressKeys.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            PGP shareKeys_pgp = new PGP(shareKeys);
            ProtonLink current = new ProtonLink(shareKeys_pgp, (string)shareInfo["LinkID"]);
            //recursively traverse the folders until we reach our file
            for (int i = 0; i < folders.Length; i++)
            {
                current = await GetFolderKeys(current, folders[i]);
            }
            return await DownloadBlockData(current.LinkID, current.ParentKeys, this.shareId);
        }

        private async Task<ProtonLink> GetFolderKeys(ProtonLink current, string folder)
        {
            JObject linkInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId + "/links/" + current.LinkID);
            string nodePrivateKey = (string)linkInfo["Link"]["NodeKey"];
            string nodePassphrase = (string)linkInfo["Link"]["NodePassphrase"];
            //Decrypt nodePassphrase
            string decryptedNodePassphrase = await current.ParentKeys.DecryptArmoredStringAsync(nodePassphrase);
            EncryptionKeys nodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
            PGP nodeKeys_pgp = new PGP(nodeKeys);
            //Get children of root folder
            JObject folderChildrenLinksInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId + "/folders/" + current.LinkID + "/children");
            // loop through links until we find the folder
            for (int i = 0; i < folderChildrenLinksInfo["Links"].Count(); i++)
            {
                //if type is folder then go one level down
                string linkName = (string)folderChildrenLinksInfo["Links"][i]["Name"];
                //Decrypt filename
                string decryptedLinkName = await nodeKeys_pgp.DecryptArmoredStringAsync(linkName);
                if (decryptedLinkName == folder)
                {

                    return new ProtonLink(nodeKeys_pgp, (string)folderChildrenLinksInfo["Links"][i]["LinkID"]);
                }
            }
            return null;
        }

        //Downloads the block data for a given link
        public async Task<Stream> DownloadBlockData(string linkID, PGP nodeKeys, string shareID)
        {
            JObject linkData = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareId + "/links/" + linkID);
            //decrypt the link private key
            string linkPrivateKey = (string)linkData["Link"]["NodeKey"];
            string linkPassphrase = (string)linkData["Link"]["NodePassphrase"];
            string decryptedLinkPassphrase = await nodeKeys.DecryptArmoredStringAsync(linkPassphrase);
            EncryptionKeys decryptedLinkKeys = new EncryptionKeys(linkPrivateKey, decryptedLinkPassphrase);
            PGP decryptedLinkKeys_pgp = new PGP(decryptedLinkKeys);
            //decode block session key
            string contentKeyPacket = (string)linkData["Link"]["FileProperties"]["ContentKeyPacket"];
            byte[] contentKeyPacket_byte = Convert.FromBase64String(contentKeyPacket);
            // fetch info for specific revision
            string targetLinkId = (string)linkData["Link"]["LinkID"];
            string linkRevisionId = (string)linkData["Link"]["FileProperties"]["ActiveRevision"]["ID"];
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


        //to delete
        public PgpPrivateKey GetParentNodePrivateKey()
        {
            FileInfo parentNodePrivateKey = new FileInfo("nodePrivateKey.asc");
            using (Stream inputStream = PgpUtilities.GetDecoderStream(parentNodePrivateKey.OpenRead()))
            {
                PgpSecretKeyRingBundle bdl = new PgpSecretKeyRingBundle(inputStream);
                IEnumerable<PgpSecretKeyRing> skr2 = bdl.GetKeyRings();
                foreach (PgpSecretKeyRing aPart in skr2)
                {
                    IEnumerable<PgpSecretKey> secList = aPart.GetSecretKeys();
                    foreach (PgpSecretKey secKey in secList)
                    {
                        PgpPrivateKey privKey = secKey.ExtractPrivateKey(parentNodePassphrase.ToCharArray());
                        if (privKey.PublicKeyPacket.Algorithm == PublicKeyAlgorithmTag.ECDH)
                        {
                            return privKey;
                        }
                    }
                }
            }
            return null;
        }

        //to delete
        public PGP GetAddressKeys()
        {
            FileInfo fileAddressPrivateKey = new FileInfo("addressPrivateKey.asc");
            EncryptionKeys addressPrivateKey = new EncryptionKeys(fileAddressPrivateKey, addressKeyPassphrase);
            return new PGP(addressPrivateKey);
        }
        public async Task Upload(Stream database, string path)
        {
            //Initially only try to upload in the root of our drive and only upload a single block file
            // STEP 1: Generate keys for encryption
            //string filename = new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString();
            string filename = path;

            // create passphrase
            Random rand = new Random();
            byte[] value = new byte[32];
            rand.NextBytes(value);
            string passphrase = Convert.ToBase64String(value);
            //File.WriteAllText("generatedCryptoMaterial/newNodeKeyPassphrase", passphrase);

            // create new node key
            PgpSecretKeyRing newNodeKeyRing = Crypto.GenerateKey(passphrase.ToCharArray());

            // get armored version of new node key
            string newNodeArmoredKeyStr = Crypto.GetArmoredKey(newNodeKeyRing);
            //File.WriteAllText("generatedCryptoMaterial/newNodeKey", newNodeArmoredKeyStr);

            //Isolated  signing/encryption keys for later use
            PgpSecretKey nodeEncPrivKey = Crypto.GetEncryptionKey(newNodeKeyRing, passphrase);
            PgpSecretKey nodeSignPrivKey = Crypto.GetSigningKey(newNodeKeyRing, passphrase);

            //Get parent nodeKey and addressKey from file (should be obtained programmatically)
            PgpPrivateKey parentNodePrivKey = GetParentNodePrivateKey();
            PGP pgp_parentNodePublicKey = new PGP(new EncryptionKeys(new FileInfo("nodePublicKey.asc"), new FileInfo("addressPrivateKey.asc"), addressKeyPassphrase));
            pgp_parentNodePublicKey.HashAlgorithmTag = HashAlgorithmTag.Sha256;
            PGP pgp_addressPrivateKey = GetAddressKeys();
            pgp_addressPrivateKey.HashAlgorithmTag = HashAlgorithmTag.Sha256;

            //encrypt the passphrase (using parent nodeKey) and create a signature (using address key).
            string encryptedNodePassphrase = await pgp_parentNodePublicKey.EncryptArmoredStringAsync(passphrase);
            MemoryStream nodePassphraseSignatureStr = new MemoryStream();
            Crypto.Sign(Encoding.UTF8.GetBytes(passphrase), nodePassphraseSignatureStr, pgp_addressPrivateKey.EncryptionKeys.SecretKey, addressKeyPassphrase.ToCharArray(), true);
            string armoredPassphraseSignature = Encoding.UTF8.GetString(nodePassphraseSignatureStr.ToArray());

            //generate session key
            SecureRandom random = new SecureRandom();
            KeyParameter key = PgpUtilities.MakeRandomKey(SymmetricKeyAlgorithmTag.Aes128, random);

            //sign the key using new node key
            MemoryStream encodedSecretKey = new MemoryStream();
            Crypto.Sign(key.GetKey(), encodedSecretKey, nodeSignPrivKey, passphrase.ToCharArray(), true);
            MemoryStream newNodeKeyStream = new MemoryStream(nodeSignPrivKey.GetEncoded());
            newNodeKeyStream.Seek(0, SeekOrigin.Begin);
            PGP pgp_newNodeKey = new PGP(new EncryptionKeys(newNodeKeyStream, passphrase));
            pgp_newNodeKey.HashAlgorithmTag = HashAlgorithmTag.Sha256;

            //encrypt filename and compute hash of filename
            //create clientUID
            string filenameHash = Crypto.ComputeFilenameHash(filename, decryptedParentNodeHashKey);
            string encryptedFilename = await pgp_parentNodePublicKey.EncryptArmoredStringAndSignAsync(filename);
            string clientUID = Util.GenerateProtonWebUID();

            //try encrypting our file (we don't want the public key encrypted session key to be part of this)
            PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            //FileStream inputFileStream = new FileStream("upload_test", FileMode.Open, FileAccess.Read);
            //MemoryStream inputFileStream = new MemoryStream(database);
            //Read max 4MB at a time worth of data from the file stream
            int numBytesToRead = 4 * 1024 * 1024;
            byte[] blockBytesMax = new byte[numBytesToRead];
            int index = 0;
            byte[] contentKeyPacket_byte = null;
            byte[] fileHash = null;
            int totalFileLength = 0;
            List<Dictionary<string, dynamic>> blockList = new List<Dictionary<string, dynamic>> { };
            //List<Dictionary<string, dynamic>> fileHash = new List<Dictionary<string, dynamic>> { };
            string createdFileID = "";
            string createdFileRevisionID = "";
            while (numBytesToRead > 0)
            {
                // Read may return anything from 0 to numBytesToRead.
                int numBytesRead = database.Read(blockBytesMax, 0, numBytesToRead);
                byte[] blockBytes = new byte[numBytesRead];
                Array.Copy(blockBytesMax, blockBytes, numBytesRead);
                totalFileLength += numBytesRead;
                // Break when the end of the file is reached.
                if (numBytesRead == 0)
                {
                    break;
                }

                MemoryStream encryptedDataStream = new MemoryStream();
                await Crypto.Encrypt(pk, new MemoryStream(blockBytes), encryptedDataStream, nodeEncPrivKey.PublicKey, key, false);
                encryptedDataStream.Seek(0, SeekOrigin.Begin);
                byte[] encDataByte = encryptedDataStream.ToArray(); //this contains the pke session key which we don't want

                if (index == 0)
                {
                    //retrieve the encrypted session key packet
                    PgpEncryptedDataGenerator.PubMethod pubMeth = (PgpEncryptedDataGenerator.PubMethod)pk.methods[0];
                    PublicKeyEncSessionPacket pke = new PublicKeyEncSessionPacket(pubMeth.pubKey.KeyId, pubMeth.pubKey.Algorithm, pubMeth.data);
                    MemoryStream encKeyPackStream = new MemoryStream();
                    pke.Encode(BcpgOutputStream.Wrap(encKeyPackStream));
                    contentKeyPacket_byte = encKeyPackStream.ToArray();

                    //create the file in the backend
                    Dictionary<string, string> createFileBody = new Dictionary<string, string>()
                        {
                            {"ContentKeyPacket", Convert.ToBase64String(contentKeyPacket_byte)},
                            {"ContentKeyPacketSignature", Encoding.UTF8.GetString(encodedSecretKey.ToArray()) },
                            {"Hash", filenameHash },
                            {"MIMEType", "application/octet-stream" },
                            {"Name", encryptedFilename },
                            {"NodeKey", newNodeArmoredKeyStr },
                            {"NodePassphrase", encryptedNodePassphrase },
                            {"NodePassphraseSignature", armoredPassphraseSignature },
                            {"ParentLinkID", ParentLinkID},
                            {"SignatureAddress", myemail},
                            {"ClientUID", clientUID }
                        };
                    string createFileBodyJSON = JsonConvert.SerializeObject(createFileBody);
                    StringContent data = new StringContent(createFileBodyJSON, Encoding.UTF8, "application/json");
                    JObject createFileResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/shares/" + shareID + "/files", data);
                    createdFileID = (string)createFileResponse["File"]["ID"];
                    createdFileRevisionID = (string)createFileResponse["File"]["RevisionID"];
                }
                //only keep the encrypted data part of the PGP message
                int encDataLength = encDataByte.Length - contentKeyPacket_byte.Length;
                encDataByte = Util.TakeSuffix(encDataByte, encDataLength);

                //Create signature of block data
                //byte[] helloWorldBytes = File.ReadAllBytes("helloworld");
                MemoryStream blockDataSignatureStr = new MemoryStream();
                Crypto.Sign(blockBytes, blockDataSignatureStr, pgp_addressPrivateKey.EncryptionKeys.SecretKey, addressKeyPassphrase.ToCharArray(), false);
                //Encrypt signature of block data
                MemoryStream encryptedBlockSignature = new MemoryStream();
                Crypto.EncryptAndSign(new MemoryStream(blockDataSignatureStr.ToArray()), encryptedBlockSignature, nodeEncPrivKey.PublicKey, nodeSignPrivKey, key, true, passphrase.ToCharArray());
                encryptedBlockSignature.Seek(0, SeekOrigin.Begin);
                string armoredEncryptedBlockSignature = Encoding.UTF8.GetString(encryptedBlockSignature.ToArray());

                //compute hash over the encrypted block data
                SHA256 mySHA256 = SHA256.Create();
                byte[] hashedEncryptedBlockData = mySHA256.ComputeHash(encDataByte);

                //store the complete string of encrypted data for later use
                if (index == 0)
                {
                    fileHash = new byte[hashedEncryptedBlockData.Length];
                    Array.Copy(hashedEncryptedBlockData, fileHash, hashedEncryptedBlockData.Length);
                }
                else
                {
                    fileHash = Util.Concat(fileHash, hashedEncryptedBlockData);
                }

                //create the block in the backend
                Dictionary<string, dynamic> createBlocksBody = new Dictionary<string, dynamic>()
                    {
                        {
                            "BlockList",
                            new Dictionary<string, dynamic>[]
                            {
                                new Dictionary<string, dynamic>()
                                {
                                    {"Index", index+1 },
                                    {"Hash", Convert.ToBase64String(hashedEncryptedBlockData) },
                                    {"EncSignature", armoredEncryptedBlockSignature  },
                                    {"Size", encDataByte.Length }
                                }
                            }
                        },
                        { "AddressID", addressID },
                        { "LinkID", createdFileID },
                        { "RevisionID", createdFileRevisionID },
                        { "ShareID", shareID }
                    };
                string createBlockBodyJSON = JsonConvert.SerializeObject(createBlocksBody);
                StringContent createBlockRequestData = new StringContent(createBlockBodyJSON, Encoding.UTF8, "application/json");
                JObject createBlockResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/blocks", createBlockRequestData);

                //upload the block to the backend URL
                string uploadURL = (string)createBlockResponse["UploadLinks"][0]["BareURL"];
                string uploadToken = (string)createBlockResponse["UploadLinks"][0]["Token"];
                var content = new MultipartFormDataContent();
                content.Add(new ByteArrayContent(encDataByte), "Block", "blob");
                var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri(uploadURL),
                    Method = HttpMethod.Post,
                };
                request.Content = content;
                request.Headers.Add("pm-storage-token", uploadToken);
                var clientX = new HttpClient();
                HttpResponseMessage response = await clientX.SendAsync(request);

                //build list of all index and upload tokens
                Dictionary<string, dynamic> nextBlock = new Dictionary<string, dynamic>()
                {
                    {"Index", index+1 },
                    {"Token", uploadToken }
                };
                blockList.Add(nextBlock);
                //build list of all file hashes
                //Dictionary<string, dynamic> nextHash = new Dictionary<string, dynamic>()
                //{
                //   {"index", index },
                //    {"hash",  Convert.ToBase64String(hashedEncryptedBlockData)}
                //};
                //fileHash.Add(nextHash);
                index++;
            }

            //File.WriteAllText("generatedCryptoMaterial/blockList", JsonConvert.SerializeObject(blockList));
            //File.WriteAllText("generatedCryptoMaterial/fileHash", JsonConvert.SerializeObject(fileHash));
            //File.WriteAllText("generatedCryptoMaterial/createdFileID", createdFileID);
            //File.WriteAllText("generatedCryptoMaterial/createdFileRevisionID", createdFileRevisionID);
            //sign the hash
            MemoryStream signedHash = new MemoryStream();
            Crypto.Sign(fileHash, signedHash, pgp_addressPrivateKey.EncryptionKeys.SecretKey, addressKeyPassphrase.ToCharArray(), true);
            string armoredSignedHash = Encoding.UTF8.GetString(signedHash.ToArray());

            //create extended attributes and encrypt them
            MemoryStream xAttrEncryptKeyStream = new MemoryStream(nodeEncPrivKey.PublicKey.GetEncoded());
            xAttrEncryptKeyStream.Seek(0, SeekOrigin.Begin);
            MemoryStream xAttrSignKeyStream = new MemoryStream(pgp_addressPrivateKey.EncryptionKeys.SecretKey.GetEncoded());
            xAttrSignKeyStream.Seek(0, SeekOrigin.Begin);
            string encryptedXAttr = await Crypto.EncryptFileExtendedAttributes(totalFileLength, new PGP(new EncryptionKeys(xAttrEncryptKeyStream, xAttrSignKeyStream, addressKeyPassphrase)));

            //update the file revision
            Dictionary<string, dynamic> updateFileRevisionBody = new Dictionary<string, dynamic>()
                    {
                        { "State", 1 },
                        { "BlockList", blockList.ToArray()},
                        { "ManifestSignature", armoredSignedHash },
                        { "SignatureAddress", myemail },
                        { "XAttr", encryptedXAttr }
                    };
            string updateFileRevisionBodyJSON = JsonConvert.SerializeObject(updateFileRevisionBody);
            StringContent updateFileRevisionRequestData = new StringContent(updateFileRevisionBodyJSON, Encoding.UTF8, "application/json");
            JObject updateFileRevisionResponse = await ProtonRequest("PUT", "https://api.protonmail.ch/drive/shares/" + shareID + "/files/" + createdFileID + "/revisions/" + createdFileRevisionID, updateFileRevisionRequestData);
            //inputFileStream.Close();
        }
    }
}