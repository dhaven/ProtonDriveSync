using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using PgpCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using static System.Windows.Forms.LinkLabel;
using Newtonsoft.Json;

namespace ProtonSecrets.StorageProvider
{
    internal class ProtonLink
    {
        public string id;
        public string parentID;
        public PGP privateKey;
        public string passphrase;
        public string nodeHashKey;
        public byte[] sessionData;
        public int encryptedSessionKeyLength;
        public string activeFileRevision;

        public ProtonLink(PGP privateKey, string passphrase, string decryptedNodeHashKey, string id, string parentID, byte[] sessionData, int encryptedSessionKeyLength, string activeFileRevision)
        {
            this.privateKey = privateKey;
            this.passphrase = passphrase;
            this.nodeHashKey = decryptedNodeHashKey;
            this.id = id;
            this.parentID = parentID;
            this.sessionData = sessionData;
            this.encryptedSessionKeyLength = encryptedSessionKeyLength;
            this.activeFileRevision = activeFileRevision;
        }

        public async static Task<ProtonLink> Initialize(string shareId, string linkId, PGP parentPrivateKey, HttpClient client)
        {
            JObject linkInfo = null;
            try
            {
                HttpResponseMessage response = await client.GetAsync("https://api.protonmail.ch/drive/shares/" + shareId + "/links/" + linkId);
                //response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody);
                linkInfo = bodyData;
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
            string nodePrivateKey = (string)linkInfo["Link"]["NodeKey"];
            string nodePassphrase = (string)linkInfo["Link"]["NodePassphrase"];
            string parentLinkId = (string)linkInfo["Link"]["ParentLinkID"];
            if ((int)linkInfo["Link"]["Type"] == 1)
            {
                string nodeHashKey = (string)linkInfo["Link"]["FolderProperties"]["NodeHashKey"];
                //Decrypt nodePassphrase
                string decryptedNodePassphrase = await parentPrivateKey.DecryptArmoredStringAsync(nodePassphrase);
                EncryptionKeys nodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
                //Decrypt nodeHashKey
                string decryptedNodeHashKey = await new PGP(nodeKeys).DecryptArmoredStringAsync(nodeHashKey);
                return new ProtonLink(new PGP(nodeKeys), decryptedNodePassphrase, decryptedNodeHashKey, linkId, parentLinkId, null, 0, "");
            }
            else
            {
                //Get the file revision
                string activeRevision = (string)linkInfo["Link"]["FileProperties"]["ActiveRevision"]["ID"];
                //Decrypt nodePassphrase
                string decryptedNodePassphrase = await parentPrivateKey.DecryptArmoredStringAsync(nodePassphrase);
                EncryptionKeys nodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
                //decrypt the sessionkey
                byte[] sessionDataDiscardedAlgo = null;
                string contentKeyPacket = (string)linkInfo["Link"]["FileProperties"]["ContentKeyPacket"];
                byte[] contentKeyPacket_byte = Convert.FromBase64String(contentKeyPacket);
                int encryptedSessionKeyLength = contentKeyPacket_byte.Length;
                BcpgInputStream bcpgInput = BcpgInputStream.Wrap(new MemoryStream(contentKeyPacket_byte));
                var packets = new List<Packet>();
                while (bcpgInput.NextPacketTag() == PacketTag.PublicKeyEncryptedSession)
                {
                    packets.Add(bcpgInput.ReadPacket());
                }
                foreach (var packet in packets)
                {
                    if (packet is PublicKeyEncSessionPacket publicKey)
                    {
                        PgpPublicKeyEncryptedData encSessionKey = new PgpPublicKeyEncryptedData(publicKey, null);
                        PgpSecretKey decryptKey = null;
                        foreach (PgpSecretKeyRing skr in nodeKeys.SecretKeys.GetKeyRings())
                        {
                            decryptKey = Crypto.GetEncryptionKey(skr, decryptedNodePassphrase);
                            if (decryptKey != null)
                            {
                                break;
                            }
                        }
                        byte[] sessionData = encSessionKey.RecoverSessionData(decryptKey.ExtractPrivateKey(decryptedNodePassphrase.ToCharArray()));
                        byte[] sessionDataDiscardedChecksum = Util.TakePrefix(sessionData, sessionData.Length - 2);
                        sessionDataDiscardedAlgo = Util.TakeSuffix(sessionDataDiscardedChecksum, sessionDataDiscardedChecksum.Length - 1);
                        
                    }
                }
                return new ProtonLink(new PGP(nodeKeys), decryptedNodePassphrase, null, linkId, parentLinkId, sessionDataDiscardedAlgo, encryptedSessionKeyLength, activeRevision);
            }
        }

        //Get an instance of a link at any level of the hierarchy given it's name
        public async static Task<ProtonLink> GetLink(string name, ProtonLink parent, string shareId, HttpClient client)
        {
            //Get children of root folder
            JObject folderChildrenLinksInfo = null;
            try
            {
                HttpResponseMessage response = await client.GetAsync("https://api.protonmail.ch/drive/shares/" + shareId + "/folders/" + parent.id + "/children");
                //response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody);
                folderChildrenLinksInfo = bodyData;
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
            // loop through links until we find the folder
            for (int i = 0; i < folderChildrenLinksInfo["Links"].Count(); i++)
            {
                string linkName = (string)folderChildrenLinksInfo["Links"][i]["Name"];
                //Decrypt filename
                string decryptedLinkName = await parent.privateKey.DecryptArmoredStringAsync(linkName);
                if (decryptedLinkName == name)
                {
                    return await ProtonLink.Initialize(shareId, (string)folderChildrenLinksInfo["Links"][i]["LinkID"], parent.privateKey, client);
                }
            }
            return null;
        }

        //return true if there is a conflict between filenames. False otherwise
        public static async Task<bool> CheckConflictingFilenames(ProtonLink parent, string filenameHash, string shareId, HttpClient client)
        {
            List<string> hashes = new List<string> { };
            hashes.Add(filenameHash);
            Dictionary<string, string[]> requestBody = new Dictionary<string, string[]>()
                        {
                            {"Hashes",hashes.ToArray()}
                        };
            string requestBodyJSON = JsonConvert.SerializeObject(requestBody);
            StringContent data = new StringContent(requestBodyJSON, Encoding.UTF8, "application/json");
            try
            {
                HttpResponseMessage response = await client.PostAsync("https://api.protonmail.ch/drive/shares/" + shareId + "/links/" + parent.id + "/checkAvailableHashes", data);
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody);
                if (bodyData["AvailableHashes"].Count() == 0)
                {
                    return true;
                }
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
            return false;
        }

        public PgpSecretKey GetSigningKey()
        {
            foreach(PgpSecretKeyRing skr in this.privateKey.EncryptionKeys.SecretKeys.GetKeyRings())
            {
                PgpSecretKey signingKey = Crypto.GetSigningKey(skr, this.passphrase);
                if(signingKey != null)
                {
                    return signingKey;
                }
            }
            return null;
        }

        public PgpSecretKey GetEncryptionKey()
        {
            foreach (PgpSecretKeyRing skr in this.privateKey.EncryptionKeys.SecretKeys.GetKeyRings())
            {
                PgpSecretKey encryptKey = Crypto.GetEncryptionKey(skr, this.passphrase);
                if (encryptKey != null)
                {
                    return encryptKey;
                }
            }
            return null;
        }
    }
}
