using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using static BCrypt.Net.BCrypt;

using PgpCore;

using ProtonDriveSync.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System.Security.Cryptography;
using System.Net;

namespace ProtonDriveSync.StorageProvider {

    public class ProtonAPI
    {

        private HttpClient client;

        internal ProtonAddress addressInfo;
        internal ProtonShare shareInfo;

        public string RefreshToken;
        public string AccessToken;

        internal class FileData
        {
            public string filenameHash;
            public string encryptedFilename;
            public PgpSecretKey nodeEncPrivKey;
            public PgpSecretKey nodeSignPrivKey;

            public FileData(string filenameHash, string encryptedFilename, PgpSecretKey nodeEncPrivKey, PgpSecretKey nodeSignPrivKey)
            {
                this.filenameHash = filenameHash;
                this.encryptedFilename = encryptedFilename;
                this.nodeEncPrivKey = nodeEncPrivKey;
                this.nodeSignPrivKey = nodeSignPrivKey;
            }
        }

        public ProtonAPI()
        {
            this.client = new HttpClient();
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls
                | SecurityProtocolType.Tls11
                | SecurityProtocolType.Tls12
                | SecurityProtocolType.Ssl3;
            this.client.DefaultRequestHeaders.Add("x-pm-appversion", "Other");
            this.client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0");
        }
        public void AddAuthHeaders(string UID, string accessToken, string refreshToken)
        {
            this.client.DefaultRequestHeaders.Remove("x-pm-uid");
            this.client.DefaultRequestHeaders.Add("x-pm-uid", UID);
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);
            this.RefreshToken = refreshToken;
            this.AccessToken = accessToken;
        }

        public async Task InitUserKeys(string email, string keyPassword)
        {
            //Get user info
            JObject userInfo;
            try
            {
                userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to initialize user keys: " + exception.Message);
            }
            JArray userKeys = (JArray)userInfo["User"]["Keys"];
            string userPrivateKey = "";
            for (int i = 0; i < userKeys.Count(); i++)
            {
                if ((int)userKeys[i]["Primary"] == 1)
                {
                    userPrivateKey = (string)userKeys[i]["PrivateKey"];
                }
            }
            EncryptionKeys encryptionKeys = new EncryptionKeys(userPrivateKey, keyPassword);
            PGP userPrivateKey_pgp = new PGP(encryptionKeys);
            try
            {
                if (this.addressInfo == null)
                {
                    this.addressInfo = await ProtonAddress.Initialize(email, userPrivateKey_pgp, this);
                }
                if (this.shareInfo == null)
                {
                    this.shareInfo = await ProtonShare.Initialize(this.addressInfo, this);
                }
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to initialize user keys: " + exception.Message);
            }
        }
        public async Task<JObject> ProtonRequest(string method, string url, StringContent data = null)
        {
            JObject bodyData;
            if (method == "POST")
            {
                try
                {
                    HttpResponseMessage response = await this.client.PostAsync(url, data);
                    if(response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        await RefreshSession();
                        response = await this.client.PostAsync(url, data);
                    }
                    string responseBody = await response.Content.ReadAsStringAsync();
                    bodyData = JObject.Parse(responseBody);
                }
                catch (HttpRequestException exception)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", exception.Message);
                    throw;
                }
            }
            else if(method == "PUT")
            {
                try
                {
                    HttpResponseMessage response = await this.client.PutAsync(url, data);
                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        await RefreshSession();
                        response = await this.client.PutAsync(url, data);
                    }
                    string responseBody = await response.Content.ReadAsStringAsync();
                    bodyData = JObject.Parse(responseBody);
                }
                catch (HttpRequestException exception)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", exception.Message);
                    throw;
                }
            }
            else
            {
                try
                {
                    HttpResponseMessage response = await this.client.GetAsync(url);
                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        await RefreshSession();
                        response = await this.client.GetAsync(url);
                    }
                    string responseBody = await response.Content.ReadAsStringAsync();
                    bodyData = JObject.Parse(responseBody);
                }
                catch (HttpRequestException exception)
                {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message :{0} ", exception.Message);
                    throw;
                }
            }
            if ((int)bodyData["Code"] != 1000)
            {
                string exceptionMessage = "API response contains an error (" + (string)bodyData["Code"] + ") : " + (string)bodyData["Error"];
                throw new Exception(exceptionMessage);
            }
            return bodyData;
        }

        public async Task<string> ComputeKeyPassword(string password)
        {
            //Get user info
            JObject userInfo;
            try
            {
                userInfo = await ProtonRequest("GET", "https://api.protonmail.ch/users");
            }catch(Exception exception)
            {
                throw new Exception("Unable to compute keyPassword: " + exception.Message);
            }
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
            JObject saltsInfo;
            try
            {
                saltsInfo = await ProtonRequest("GET", "https://api.protonmail.ch/keys/salts");
            }catch(Exception exception)
            {
                throw new Exception("Unable to compute keyPassword: " + exception.Message);
            }
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

        public async Task<AccountConfiguration> Authenticate(string username, string password)
        {
            Dictionary<string, string> authPayload = new Dictionary<string, string>();
            authPayload["Username"] = username;
            string json = JsonConvert.SerializeObject(authPayload, Formatting.Indented);
            StringContent data = new StringContent(json, Encoding.UTF8, "application/json");
            JObject authInfo;
            try
            {
                authInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/info", data);
            }catch(Exception exception)
            {
                throw new Exception("Unable to authenticate user: " + exception.Message);
            }
            //getSrp
            Dictionary<string,string> authData = await SRP.GetSrp(authInfo, username, password);
            //CallAndValidate
            Dictionary<string, string> SRPAuth = new Dictionary<string, string>();
            SRPAuth["Username"] = username;
            SRPAuth["ClientEphemeral"] = authData["clientEphemeral"];
            SRPAuth["ClientProof"] = authData["clientProof"];
            SRPAuth["SRPSession"] = (string)authInfo["SRPSession"];
            string SRPAuthJson = JsonConvert.SerializeObject(SRPAuth);
            StringContent SRPAuthData = new StringContent(SRPAuthJson, Encoding.UTF8, "application/json");
            JObject srpResult;
            try
            {
                srpResult = await ProtonRequest("POST", "https://api.protonmail.ch/auth", SRPAuthData);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to authenticate user: " + exception.Message);
            }
            if (authData["expectedServerProof"] == (string)srpResult["ServerProof"])
            {
                //add headers for later requests
                this.client.DefaultRequestHeaders.Remove("x-pm-uid");
                this.client.DefaultRequestHeaders.Add("x-pm-uid", (string)srpResult["UID"]);
                this.client.DefaultRequestHeaders.Remove("Authorization");
                this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)srpResult["AccessToken"]);
                this.RefreshToken = (string)srpResult["RefreshToken"];
                this.AccessToken = (string)srpResult["AccessToken"];
                if (((string)srpResult["Scope"]).Split(' ').Contains("twofactor"))
                {
                    return new AccountConfiguration("", username, (string)srpResult["UID"], (string)srpResult["AccessToken"], (string)srpResult["RefreshToken"], true);
                }
                return new AccountConfiguration("", username, (string)srpResult["UID"], (string)srpResult["AccessToken"], (string)srpResult["RefreshToken"], false);
            }
            throw new Exception("Unable to authenticate user: An unexpected error occured");
        }

        public async Task Validate2fa(string twofa)
        {
            Dictionary<string, string> twoFAAuth = new Dictionary<string, string>();
            twoFAAuth["TwoFactorCode"] = twofa;
            string twoFAAuthJson = JsonConvert.SerializeObject(twoFAAuth, Formatting.Indented);
            StringContent twoFAAuthData = new StringContent(twoFAAuthJson, Encoding.UTF8, "application/json");
            try
            {
                JObject twoFAAuthInfo = await ProtonRequest("POST", "https://api.protonmail.ch/auth/2fa", twoFAAuthData);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to validate 2fa: " + exception.Message);
            }
        }

        public async Task RefreshSession()
        {
            Dictionary<string, string> refreshData = new Dictionary<string, string>();
            refreshData["ResponseType"] = "token";
            refreshData["GrantType"] = "refresh_token";
            refreshData["RefreshToken"] = this.RefreshToken;
            refreshData["RedirectURI"] = "http://protonmail.ch";
            string refreshDataJson = JsonConvert.SerializeObject(refreshData);
            StringContent data = new StringContent(refreshDataJson, Encoding.UTF8, "application/json");
            JObject refreshResult;
            try
            {
                refreshResult = await ProtonRequest("POST", "https://api.protonmail.ch/auth/refresh", data);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to refresh session: " + exception.Message);
                //if unable to refresh tokens it is possible the account file is corrupted in which case
                //we should prompt the user to login once again
            }
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.client.DefaultRequestHeaders.Add("Authorization", "Bearer " + (string)refreshResult["AccessToken"]);
            this.RefreshToken = (string)refreshResult["RefreshToken"];
            this.AccessToken = (string)refreshResult["AccessToken"];
        }

        public async Task Logout()
        {
            JObject bodyData;
            try
            {
                HttpResponseMessage response = await client.DeleteAsync("https://api.protonmail.ch/auth");
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    await RefreshSession();
                    response = await client.DeleteAsync("https://api.protonmail.ch/auth");
                }
                string responseBody = await response.Content.ReadAsStringAsync();
                bodyData = JObject.Parse(responseBody);
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                throw new Exception("Unable to logout: " + exception.Message);
            }
            if ((int)bodyData["Code"] != 1000)
            {
                string exceptionMessage = "API response contains an error (" + (string)bodyData["Code"] + ") : " + (string)bodyData["Error"];
                throw new Exception("Unable to logout: " + exceptionMessage);
            }
            this.client.DefaultRequestHeaders.Remove("x-pm-uid");
            this.client.DefaultRequestHeaders.Remove("Authorization");
            this.RefreshToken = "";
            this.AccessToken = "";
            this.addressInfo = null;
            this.shareInfo = null;
        }

        public async Task<IEnumerable<ProtonDriveItem>> GetRootChildren()
        {
            JObject linkInfo;
            try
            {
                linkInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/links/" + this.shareInfo.linkID);
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to fetch root folder content: " + exception.Message);
            }
            string rootNodePrivateKey = (string)linkInfo["Link"]["NodeKey"];
            string rootNodePassphrase = (string)linkInfo["Link"]["NodePassphrase"];
            //Decrypt root nodePassphrase
            string decryptedRootNodePassphrase = await this.shareInfo.privateKey.DecryptArmoredStringAsync(rootNodePassphrase);
            EncryptionKeys nodeKeys = new EncryptionKeys(rootNodePrivateKey, decryptedRootNodePassphrase);
            PGP nodeKeys_pgp = new PGP(nodeKeys);
            try
            {
                return await GetChildren(nodeKeys_pgp, this.shareInfo.linkID, this.shareInfo.id);
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to fetch root folder content: " + exception.Message);
            }
        }
        //returns a list of ProtonDriveItems that are the children of Link Id
        public async Task<IEnumerable<ProtonDriveItem>> GetChildren(PGP parentKeys, string linkId, string shareId)
        {
            List<ProtonDriveItem> children = new List<ProtonDriveItem>();
            JObject childrenLinks;
            try
            {
                childrenLinks = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareId + "/folders/" + linkId + "/children");
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to fetch folder contents: " + exception.Message);
            }
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
                nextChild.ShareId = shareId;
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
            try
            {
                string[] folders = path.Split(new string[] { "/" }, StringSplitOptions.RemoveEmptyEntries);
                ProtonLink nextLink = await ProtonLink.Initialize(this.shareInfo.id, this.shareInfo.linkID, this.shareInfo.privateKey, this);
                //recursively traverse the folders until we reach our file
                for (int i = 0; i < folders.Length; i++)
                {
                    nextLink = await ProtonLink.GetLink(folders[i], nextLink, this.shareInfo.id, this);
                }
                return await DownloadBlockData(nextLink);
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to download file: " + exception.Message);
            }
        }

        //Downloads the block data for a given link
        private async Task<Stream> DownloadBlockData(ProtonLink link)
        {
            try
            {
                JObject linkData = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/links/" + link.id);
                //decode block session key
                string contentKeyPacket = (string)linkData["Link"]["FileProperties"]["ContentKeyPacket"];
                byte[] contentKeyPacket_byte = Convert.FromBase64String(contentKeyPacket);
                // fetch info for specific revision
                string targetLinkId = (string)linkData["Link"]["LinkID"];
                string linkRevisionId = (string)linkData["Link"]["FileProperties"]["ActiveRevision"]["ID"];
                JObject linkRevisionInfo = await ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/files/" + targetLinkId + "/revisions/" + linkRevisionId);
                JArray blocks = (JArray)linkRevisionInfo["Revision"]["Blocks"];
                byte[] keepassDB_bytes = new byte[] { };
                for (int i = 0; i < blocks.Count(); i++)
                {
                    string revisionBlockURL = (string)blocks[i]["URL"];
                    // fetch and decrypt unique block
                    HttpResponseMessage blockResponse = await client.GetAsync(revisionBlockURL);
                    if (blockResponse.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        await RefreshSession();
                        blockResponse = await client.GetAsync(revisionBlockURL);
                    }
                    Stream encData = await blockResponse.Content.ReadAsStreamAsync();
                    byte[] block;
                    using (var memoryStream = new MemoryStream())
                    {
                        encData.CopyTo(memoryStream);
                        block = memoryStream.ToArray();
                    }
                    MemoryStream outputStream = new MemoryStream();
                    await link.privateKey.DecryptStreamAsync(new MemoryStream(Util.Concat(contentKeyPacket_byte, block)), outputStream);
                    //write this portion of the stream to our overall stream
                    keepassDB_bytes = Util.Concat(keepassDB_bytes, outputStream.ToArray());
                }
                return new MemoryStream(keepassDB_bytes);
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to download file contents: " + exception.Message);
            }
        }

        public async Task Upload(Stream database, string path)
        {
            //split the filename into folders
            //recursively search until we find the nodeKeys of the folder containing our file
            string[] folders = path.Split(new string[] { "/" }, StringSplitOptions.RemoveEmptyEntries);
            string filename = folders[folders.Length - 1];
            //initialize the root link
            ProtonLink rootLink;
            try
            {
                rootLink = await ProtonLink.Initialize(this.shareInfo.id, this.shareInfo.linkID, this.shareInfo.privateKey, this);
            }
            catch(Exception exception)
            {
                throw new Exception("Unable to upload file: " + exception.Message);
            }
            //initialize all folder links part of the path
            ProtonLink lastParentLink = rootLink;
            for (int i = 0; i < folders.Length - 1; i++)
            {
                try
                {
                    ProtonLink nextLink = await ProtonLink.GetLink(folders[i], lastParentLink, this.shareInfo.id, this);
                    lastParentLink = nextLink;
                }catch(Exception exception)
                {
                    throw new Exception("failed to upload file: " + exception.Message);
                }
            }
            //check what is the first available hash and see if it conflicts with our filename
            string filenameHash = Crypto.ComputeFilenameHash(filename, lastParentLink.nodeHashKey);
            try
            {
                if (await ProtonLink.CheckConflictingFilenames(lastParentLink, filenameHash, this.shareInfo.id, this))
                {
                    await UpdateFile(database, filename, lastParentLink);
                }
                else
                {
                    await CreateFile(database, filename, lastParentLink);
                }
            }catch(Exception exception)
            {
                throw new Exception("Error occured during file upload: " + exception.Message);
            }

        }

        private async Task CreateFile(Stream database, string filename, ProtonLink parent)
        {
            // create passphrase
            Random rand = new Random();
            byte[] value = new byte[32];
            rand.NextBytes(value);
            string passphrase = Convert.ToBase64String(value);

            // create new node key
            PgpSecretKeyRing newNodeKeyRing = Crypto.GenerateKey(passphrase.ToCharArray());

            // get armored version of new node key
            string newNodeArmoredKeyStr = Crypto.GetArmoredKey(newNodeKeyRing);

            //Isolate signing/encryption keys for later use
            PgpSecretKey nodeEncPrivKey = Crypto.GetEncryptionKey(newNodeKeyRing, passphrase);
            PgpSecretKey nodeSignPrivKey = Crypto.GetSigningKey(newNodeKeyRing, passphrase);

            //get parent public key for filename encryption
            PGP parentPrivateKey = parent.privateKey;
            PgpSecretKey parentNodeEncPrivKey = null;
            foreach (PgpSecretKeyRing parentKey in parentPrivateKey.EncryptionKeys.SecretKeys.GetKeyRings())
            {
                PgpSecretKey encKey = Crypto.GetEncryptionKey(parentKey, parent.passphrase);
                if (encKey != null)
                {
                    parentNodeEncPrivKey = encKey;
                }
            }

            //encrypt the passphrase (using parent nodeKey) and create a signature (using address key).
            MemoryStream encryptedNodePassphraseStream = new MemoryStream();
            PgpEncryptedDataGenerator pk1 = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            await Crypto.Encrypt(pk1, new MemoryStream(Encoding.UTF8.GetBytes(passphrase)), encryptedNodePassphraseStream, parentNodeEncPrivKey.PublicKey, null, true);
            encryptedNodePassphraseStream.Seek(0, SeekOrigin.Begin);
            string encryptedNodePassphrase = Encoding.UTF8.GetString(encryptedNodePassphraseStream.ToArray());
            MemoryStream nodePassphraseSignatureStr = new MemoryStream();
            Crypto.Sign(Encoding.UTF8.GetBytes(passphrase), nodePassphraseSignatureStr, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray(), true);
            string armoredPassphraseSignature = Encoding.UTF8.GetString(nodePassphraseSignatureStr.ToArray());

            //generate session key
            SecureRandom random = new SecureRandom();
            KeyParameter key = PgpUtilities.MakeRandomKey(SymmetricKeyAlgorithmTag.Aes128, random);
            //sign the key using new node key
            MemoryStream encodedSecretKey = new MemoryStream();
            Crypto.Sign(key.GetKey(), encodedSecretKey, nodeSignPrivKey, passphrase.ToCharArray(), true);

            //encrypt filename and compute hash of filename
            //create clientUID
            string filenameHash = Crypto.ComputeFilenameHash(filename, parent.nodeHashKey);
            string encryptedFilename = await Crypto.EncryptArmoredStringAndSignAsync(filename, parentNodeEncPrivKey.PublicKey, null, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray());
            string clientUID = Util.GenerateProtonWebUID();

            //try encrypting our file (we don't want the public key encrypted session key to be part of this)
            PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            //Read max 4MB at a time worth of data from the file stream
            int numBytesToRead = 4 * 1024 * 1024;
            byte[] blockBytesMax = new byte[numBytesToRead];
            int index = 0;
            byte[] contentKeyPacket_byte = null;
            byte[] fileHash = null;
            int totalFileLength = 0;
            List<Dictionary<string, dynamic>> blockList = new List<Dictionary<string, dynamic>> { };
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
                            {"ParentLinkID", parent.id},
                            {"SignatureAddress", this.addressInfo.email},
                            {"ClientUID", clientUID }
                        };
                    string createFileBodyJSON = JsonConvert.SerializeObject(createFileBody);
                    StringContent data = new StringContent(createFileBodyJSON, Encoding.UTF8, "application/json");
                    try
                    {
                        JObject createFileResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/files", data);
                        createdFileID = (string)createFileResponse["File"]["ID"];
                        createdFileRevisionID = (string)createFileResponse["File"]["RevisionID"];
                    }catch(Exception exception)
                    {
                        throw new Exception("Unable to create file in Drive: " + exception.Message);
                    }
                }
                //only keep the encrypted data part of the PGP message
                int encDataLength = encDataByte.Length - contentKeyPacket_byte.Length;
                encDataByte = Util.TakeSuffix(encDataByte, encDataLength);

                //Create signature of block data
                MemoryStream blockDataSignatureStr = new MemoryStream();
                Crypto.Sign(blockBytes, blockDataSignatureStr, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray(), false);
                //Encrypt signature of block data
                string armoredEncryptedBlockSignature = "";
                using (Stream armoredEncryptedBlockSignatureStr = new MemoryStream())
                {
                    await Crypto.EncryptStreamAndSignAsync(new MemoryStream(blockDataSignatureStr.ToArray()), armoredEncryptedBlockSignatureStr, nodeEncPrivKey.PublicKey, key, nodeSignPrivKey, passphrase.ToCharArray());
                    armoredEncryptedBlockSignatureStr.Seek(0, SeekOrigin.Begin);
                    armoredEncryptedBlockSignature = await armoredEncryptedBlockSignatureStr.GetStringAsync();
                }

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
                        { "AddressID", addressInfo.id },
                        { "LinkID", createdFileID },
                        { "RevisionID", createdFileRevisionID },
                        { "ShareID", this.shareInfo.id }
                    };
                string createBlockBodyJSON = JsonConvert.SerializeObject(createBlocksBody);
                StringContent createBlockRequestData = new StringContent(createBlockBodyJSON, Encoding.UTF8, "application/json");
                JObject createBlockResponse;
                try
                {
                    createBlockResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/blocks", createBlockRequestData);
                }
                catch(Exception exception)
                {
                    throw new Exception("Unable to create file in Drive: " + exception.Message);
                }
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
                try
                {
                    HttpResponseMessage response = await clientX.SendAsync(request);
                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        await RefreshSession();
                        response = await clientX.SendAsync(request);
                    }
                    //also check response is valid
                }
                catch (HttpRequestException exception)
                {
                    throw new Exception("Unable to create file in drive: " + exception.Message);
                }
                //build list of all index and upload tokens
                Dictionary<string, dynamic> nextBlock = new Dictionary<string, dynamic>()
                    {
                        {"Index", index+1 },
                        {"Token", uploadToken }
                    };
                blockList.Add(nextBlock);
                index++;
            }
            //sign the hash
            MemoryStream signedHash = new MemoryStream();
            Crypto.Sign(fileHash, signedHash, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray(), true);
            string armoredSignedHash = Encoding.UTF8.GetString(signedHash.ToArray());

            //create extended attributes and encrypt them
            string encryptedXAttr = await Crypto.EncryptFileExtendedAttributes(totalFileLength, nodeEncPrivKey.PublicKey, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray());

            //update the file revision
            Dictionary<string, dynamic> updateFileRevisionBody = new Dictionary<string, dynamic>()
                    {
                        { "State", 1 },
                        { "BlockList", blockList.ToArray()},
                        { "ManifestSignature", armoredSignedHash },
                        { "SignatureAddress", this.addressInfo.email },
                        { "XAttr", encryptedXAttr }
                    };
            string updateFileRevisionBodyJSON = JsonConvert.SerializeObject(updateFileRevisionBody);
            StringContent updateFileRevisionRequestData = new StringContent(updateFileRevisionBodyJSON, Encoding.UTF8, "application/json");
            try
            {
                JObject updateFileRevisionResponse = await ProtonRequest("PUT", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/files/" + createdFileID + "/revisions/" + createdFileRevisionID, updateFileRevisionRequestData);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to create file in drive: " + exception.Message);
            }
            
        }

        private async Task UpdateFile(Stream database, string filename, ProtonLink lastParentLink)
        {
            ProtonLink link = await ProtonLink.GetLink(filename, lastParentLink, this.shareInfo.id, this);
            string clientUID = Util.GenerateProtonWebUID();

            //create new file revision
            Dictionary<string, dynamic> createFileRevisionBody = new Dictionary<string, dynamic>()
                    {
                        { "CurrentRevisionID", link.activeFileRevision },
                        { "ClientUID", clientUID},
                    };
            string createFileRevisionBodyJSON = JsonConvert.SerializeObject(createFileRevisionBody);
            StringContent createFileRevisionRequestData = new StringContent(createFileRevisionBodyJSON, Encoding.UTF8, "application/json");
            JObject createFileRevisionResponse;
            try
            {
                createFileRevisionResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/files/" + link.id + "/revisions", createFileRevisionRequestData);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to update file in drive: " + exception.Message);
            }
            string createdFileRevisionID = (string)createFileRevisionResponse["Revision"]["ID"];

            //Isolated  signing/encryption keys for later use
            PgpSecretKey nodeEncPrivKey = link.GetEncryptionKey();
            PgpSecretKey nodeSignPrivKey = link.GetSigningKey();

            //Get the session key associated with our link
            KeyParameter key = new KeyParameter(link.sessionData);

            //try encrypting our file (we don't want the public key encrypted session key to be part of this)
            PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            //Read max 4MB at a time worth of data from the file stream
            int numBytesToRead = 4 * 1024 * 1024;
            byte[] blockBytesMax = new byte[numBytesToRead];
            int index = 0;
            byte[] fileHash = null;
            int totalFileLength = 0;
            List<Dictionary<string, dynamic>> blockList = new List<Dictionary<string, dynamic>> { };
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

                //only keep the encrypted data part of the PGP message
                int encDataLength = encDataByte.Length - link.encryptedSessionKeyLength;
                encDataByte = Util.TakeSuffix(encDataByte, encDataLength);

                //Create signature of block data
                //byte[] helloWorldBytes = File.ReadAllBytes("helloworld");
                MemoryStream blockDataSignatureStr = new MemoryStream();
                Crypto.Sign(blockBytes, blockDataSignatureStr, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray(), false);
                //Encrypt signature of block data
                string armoredEncryptedBlockSignature = await Crypto.EncryptArmoredStringAndSignAsync(Encoding.UTF8.GetString(blockDataSignatureStr.ToArray()), nodeEncPrivKey.PublicKey, key, nodeSignPrivKey, link.passphrase.ToCharArray());

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
                        { "AddressID", addressInfo.id },
                        { "LinkID", link.id },
                        { "RevisionID", createdFileRevisionID },
                        { "ShareID", this.shareInfo.id }
                    };
                string createBlockBodyJSON = JsonConvert.SerializeObject(createBlocksBody);
                StringContent createBlockRequestData = new StringContent(createBlockBodyJSON, Encoding.UTF8, "application/json");
                JObject createBlockResponse;
                try
                {
                    createBlockResponse = await ProtonRequest("POST", "https://api.protonmail.ch/drive/blocks", createBlockRequestData);
                }
                catch (Exception exception)
                {
                    throw new Exception("Unable to update file in drive: " + exception.Message);
                }
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
                try
                {
                    HttpResponseMessage response = await clientX.SendAsync(request);
                    //check response is ok
                }catch(HttpRequestException exception)
                {
                    throw new Exception("Unable to update file in drive: " + exception.Message);
                }

                //build list of all index and upload tokens
                Dictionary<string, dynamic> nextBlock = new Dictionary<string, dynamic>()
                    {
                        {"Index", index+1 },
                        {"Token", uploadToken }
                    };
                blockList.Add(nextBlock);
                index++;
            }
            //sign the hash
            MemoryStream signedHash = new MemoryStream();
            Crypto.Sign(fileHash, signedHash, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray(), true);
            string armoredSignedHash = Encoding.UTF8.GetString(signedHash.ToArray());

            //create extended attributes and encrypt them
            MemoryStream xAttrEncryptKeyStream = new MemoryStream(nodeEncPrivKey.PublicKey.GetEncoded());
            xAttrEncryptKeyStream.Seek(0, SeekOrigin.Begin);
            MemoryStream xAttrSignKeyStream = new MemoryStream(addressInfo.privateKey.EncryptionKeys.SecretKey.GetEncoded());
            xAttrSignKeyStream.Seek(0, SeekOrigin.Begin);
            string encryptedXAttr = await Crypto.EncryptFileExtendedAttributes(totalFileLength, nodeEncPrivKey.PublicKey, addressInfo.privateKey.EncryptionKeys.SecretKey, addressInfo.passphrase.ToCharArray());

            //update the file revision
            Dictionary<string, dynamic> updateFileRevisionBody = new Dictionary<string, dynamic>()
                    {
                        { "State", 1 },
                        { "BlockList", blockList.ToArray()},
                        { "ManifestSignature", armoredSignedHash },
                        { "SignatureAddress", this.addressInfo.email },
                        { "XAttr", encryptedXAttr }
                    };
            string updateFileRevisionBodyJSON = JsonConvert.SerializeObject(updateFileRevisionBody);
            StringContent updateFileRevisionRequestData = new StringContent(updateFileRevisionBodyJSON, Encoding.UTF8, "application/json");
            try
            {
                JObject updateFileRevisionResponse = await ProtonRequest("PUT", "https://api.protonmail.ch/drive/shares/" + this.shareInfo.id + "/files/" + link.id + "/revisions/" + createdFileRevisionID, updateFileRevisionRequestData);
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to update file in drive: " + exception.Message);
            }
        }
    }
}