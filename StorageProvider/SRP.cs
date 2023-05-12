using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

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

    internal sealed class CompositeDisposable : IDisposable
    {
        private readonly ConcurrentQueue<IDisposable> _disposables = new ConcurrentQueue<IDisposable>();

        public void Add(IDisposable disposable)
        {
            if (disposable == null)
                throw new ArgumentNullException(nameof(disposable));

            _disposables.Enqueue(disposable);
        }

        public void Dispose()
        {
            while (_disposables.TryDequeue(out IDisposable disposable))
                disposable.Dispose();
        }
    }

    internal static class DisposableExtensions
    {
        /// <seealso href="https://github.com/reactiveui/ReactiveUI/blob/main/src/ReactiveUI/Mixins/DisposableMixins.cs#L28">
        /// Adapted from ReactiveUI.
        /// </seealso>
        public static T DisposeWith<T>(this T @this, CompositeDisposable disposables)
            where T : IDisposable
        {
            if (@this == null)
                throw new ArgumentNullException(nameof(@this));
            if (disposables == null)
                throw new ArgumentNullException(nameof(disposables));

            disposables.Add(@this);
            return @this;
        }
    }
}