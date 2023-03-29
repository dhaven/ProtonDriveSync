namespace ProtonSecrets.StorageProvider
{
    public class SRP
    {
        public string ClientEphemeral;
        public string ClientProof;
        public byte[] expectedServerProof;

        public SRP(string clientEphemeral, string clientProof, byte[] expectedServerProof)
        {
            this.ClientEphemeral = clientEphemeral;
            this.ClientProof = clientProof;
            this.expectedServerProof = expectedServerProof;
        }
    }
}