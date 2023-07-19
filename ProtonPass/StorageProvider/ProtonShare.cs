using Newtonsoft.Json.Linq;
using PgpCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace ProtonPass.StorageProvider
{
    internal class ProtonShare
    {
        public PGP privateKey;
        public string id;
        public string passphrase;
        public string linkID;

        public ProtonShare(PGP privateKey, string id, string passphrase, string linkID)
        {
            this.privateKey = privateKey;
            this.id = id;
            this.passphrase = passphrase;
            this.linkID = linkID;
        }

        public static async Task<ProtonShare> Initialize(ProtonAddress addressInfo, ProtonAPI api)
        {
            JObject sharesInfo;
            try
            {
                sharesInfo = await api.ProtonRequest("GET", "https://api.protonmail.ch/drive/shares");
            }
            catch (Exception exception)
            {
                throw new Exception("unable to initialize shares info: " +  exception.Message);
            }
            JArray shares = (JArray)sharesInfo["Shares"];
            string shareId = "";
            for (int i = 0; i < shares.Count(); i++)
            {
                if (shares[i]["CreationTime"].ToString() == "")
                {
                    shareId = (string)shares[i]["ShareID"];
                }
            }
            JObject shareInfo;
            try
            {
                shareInfo = await api.ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareId);
            }
            catch (Exception exception)
            {
                throw new Exception ("unable to initialize specific share info: " + exception.Message);
            }
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];

            //Decrypt sharePassphrase
            string decryptedPassphrase = await addressInfo.privateKey.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            return new ProtonShare(new PGP(shareKeys), shareId, decryptedPassphrase, (string)shareInfo["LinkID"]);
        }
    }
}
