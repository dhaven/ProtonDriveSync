using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using PgpCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace ProtonSecrets.StorageProvider
{
    internal class ProtonLink
    {
        public string id;
        public string parentID;
        public PGP privateKey;
        public string passphrase;
        public string nodeHashKey;

        public ProtonLink(PGP privateKey, string passphrase, string decryptedNodeHashKey, string id, string parentID)
        {
            this.privateKey = privateKey;
            this.passphrase = passphrase;
            this.nodeHashKey = decryptedNodeHashKey;
            this.id = id;
            this.parentID = parentID;
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
                return new ProtonLink(new PGP(nodeKeys), decryptedNodePassphrase, decryptedNodeHashKey, linkId, parentLinkId);
            }
            else
            {
                //Decrypt nodePassphrase
                string decryptedNodePassphrase = await parentPrivateKey.DecryptArmoredStringAsync(nodePassphrase);
                EncryptionKeys nodeKeys = new EncryptionKeys(nodePrivateKey, decryptedNodePassphrase);
                return new ProtonLink(new PGP(nodeKeys), decryptedNodePassphrase, null, linkId, parentLinkId);
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
                //if type is folder then go one level down
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
    }
}
