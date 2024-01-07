using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PGPEncryption.Models;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

namespace PGPEncryption.Controllers
{
    
    public static class Constants
    {
        public const int LARGEBUFFERSIZE = 1048576;
    }

    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Index(PGPEncryptionModel model)
        {
            if (ModelState.IsValid)
            {

                List<PgpPublicKey> publicKeys = GetPgpPublicKeys(model.PGPPublicKeyBlockInput);

                Stream inputStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(model.PGPInputToEncrypt));
                
                // Something went wrong in GetPgpPublicKeys
                // ViewData["ExceptionMessage"] should display error message
                if (publicKeys.Count == 0) 
                {
                    return View(model);
                }

                
                bool foundEncryptionKey = false;
                foreach (PgpPublicKey publicKey in publicKeys) 
                {
                    if (publicKey.IsEncryptionKey) 
                    {
                        foundEncryptionKey = true;
                    }
                }

                // In case keys are found, but none are marked for encryption.
                if (!foundEncryptionKey) 
                {
                    ViewData["NoEncryptionKey"] = true;
                    return View(model);
                }               

                var encryptedMessageStreamX = new MemoryStream();
                Encrypt(inputStream, encryptedMessageStreamX, "", publicKeys);

                string PgpOutputMessage = System.Text.Encoding.UTF8.GetString(encryptedMessageStreamX.ToArray());

                ViewData["PgpOutputMessage"] = PgpOutputMessage;

                return View(model);
            }
            else
            { 
                return RedirectToAction("Index");
            }

        }


        // Credit for Encrypt-function, https://github.com/bertjohnson/OpaqueMail

        /// <summary>
        /// Attempt to encrypt a message using PGP with the specified public key(s).
        /// </summary>
        /// <param name="messageStream">Stream containing the message to encrypt.</param>
        /// <param name="encryptedMessageStream">Stream to write the encrypted message into.</param>
        /// <param name="fileName">File name of for the message.</param>
        /// <param name="recipientPublicKeys">Collection of BouncyCastle public keys to be used for encryption.</param>
        /// <param name="symmetricKeyAlgorithmTag">The symmetric key algorithm tag to use for encryption.</param>
        /// <param name="armor">Whether to wrap the message with ASCII armor.</param>
        /// <returns>Whether the encryption completed successfully.</returns>
        public static bool Encrypt(Stream messageStream, Stream encryptedMessageStream, string fileName, IEnumerable<PgpPublicKey> recipientPublicKeys, SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag = SymmetricKeyAlgorithmTag.TripleDes, bool armor = true)
        {

            // Allow any of the corresponding keys to be used for decryption.
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(symmetricKeyAlgorithmTag, true, new SecureRandom());
            foreach (PgpPublicKey publicKey in recipientPublicKeys)
            {
                encryptedDataGenerator.AddMethod(publicKey);
            }

            // Handle optional ASCII armor.
            if (armor)
            {
                using (Stream armoredStream = new ArmoredOutputStream(encryptedMessageStream))
                {
                    using (Stream encryptedStream = encryptedDataGenerator.Open(armoredStream, new byte[Constants.LARGEBUFFERSIZE]))
                    {
                        PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Uncompressed);
                        using (Stream compressedStream = compressedDataGenerator.Open(encryptedStream))
                        {
                            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                            using (Stream literalDataStream = literalDataGenerator.Open(encryptedStream, PgpLiteralData.Utf8, fileName, DateTime.Now, new byte[Constants.LARGEBUFFERSIZE]))
                            {
                                messageStream.Seek(0, SeekOrigin.Begin);
                                messageStream.CopyTo(literalDataStream);
                            }
                        }

                    }
                }
            }
            else
            {
                using (Stream encryptedStream = encryptedDataGenerator.Open(encryptedMessageStream, new byte[Constants.LARGEBUFFERSIZE]))
                {
                    PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Uncompressed);
                    using (Stream compressedStream = compressedDataGenerator.Open(encryptedStream))
                    {
                        PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
                        using (Stream literalDataStream = literalDataGenerator.Open(encryptedStream, PgpLiteralData.Binary, fileName, DateTime.Now, new byte[Constants.LARGEBUFFERSIZE]))
                        {
                            messageStream.Seek(0, SeekOrigin.Begin);
                            messageStream.CopyTo(literalDataStream);
                        }
                    }

                }
            }

            return true;
        }

        public List<PgpPublicKey> GetPgpPublicKeys(string PGPPublicKeyBlockInput)         
        {
            // Process input from view to inputStream
            Stream inputStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(PGPPublicKeyBlockInput));
            inputStream.Position = 0;

            // Decode to ArmoredInputStream or BcpgInputStream
            Stream keyIn = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pubRings;

            // In case of exceptions such as invalid apparmor, invalid crc and so on
            try
            {
                pubRings = new PgpPublicKeyRingBundle(keyIn);
            }
            catch (Exception ex)
            {
                // Make-nonstatic to enable
                // Save exeption message in viewdata for dispaying in view
                
                ViewData["ExceptionMessage"] = ex.Message;

                // Create empty PgpPublicKeyRingBundle
                List<PgpObject> pgpObjects = new List<PgpObject>();
                pubRings = new PgpPublicKeyRingBundle(pgpObjects);
            }

            // Convert PgpPublicKeyRingBundle to list of PgpPublicKeys

            List<PgpPublicKey> publicKeyList = new List<PgpPublicKey>();

            foreach (PgpPublicKeyRing keyRing in pubRings.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    publicKeyList.Add(key);
                }
            }

            return publicKeyList;
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}