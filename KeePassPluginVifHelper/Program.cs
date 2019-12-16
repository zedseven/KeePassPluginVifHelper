using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace KeePassPluginVifHelper
{
	internal class Program
	{
		private static void Main(string[] args)
		{
			if (args.Length != 2)
			{
				Console.WriteLine("Please supply the path of the plugin Version Information File you wish to sign, and the path to the RSA private key in XML format.");
				Console.ReadKey();
				return;
			}

			string inputPath = args[0];
			string privateKeyPath = args[1];

			if (inputPath == null || privateKeyPath  == null || !File.Exists(inputPath) || !File.Exists(privateKeyPath))
			{
				Console.WriteLine("Something is wrong with one or more of the paths you provided.");
				Console.ReadKey();
				return;
			}

			string outputDir = Path.GetDirectoryName(inputPath);

			//Create a temporary directory to do all the work
			string tempDir = Path.Combine(Path.GetTempPath(), "KeePassPluginVifHelper", Guid.NewGuid().ToString());
			string tempPath = Path.Combine(tempDir, Path.GetFileName(inputPath));

			if (!Directory.Exists(tempDir))
				Directory.CreateDirectory(tempDir);

			File.Copy(inputPath, tempPath);
			Console.WriteLine("Everything is okay.");

			SignVif(tempPath, privateKeyPath);
			Console.WriteLine("Signed the VIF.");

			string finalVifPath = GZipFile(tempPath);
			Console.WriteLine("GZipped the signed VIF.");

			string outputPath = Path.Combine(outputDir, Path.GetFileName(finalVifPath));
			if (File.Exists(outputPath))
			{
				Console.WriteLine($"The file '{outputPath}' already exists. Please move or remove it, then try again.");
				Console.ReadKey();
				return;
			}
			File.Copy(finalVifPath, outputPath);
			Console.WriteLine($"Operation complete. The prepared VIF can be found at '{outputPath}'.");

			Console.ReadKey();
		}

		/// <summary>
		/// Signs a KeePass Plugin Version Information File in-place according to the
		/// <a href="https://keepass.info/help/v2_dev/plg_index.html#upd">official development instructions</a>.
		/// </summary>
		/// <param name="sourcePath">The filepath of the source VIF.</param>
		/// <param name="privateKeyPath">The filepath of the RSA private key file, in XML format.</param>
		private static void SignVif(string sourcePath, string privateKeyPath)
		{
			string[] vifLines = File.ReadAllLines(sourcePath, Encoding.UTF8);

			if (vifLines.Length < 2)
				return;

			string payload = "";
			for (int i = 1; i < vifLines.Length - 1; i++)
			{
				string newLine = vifLines[i].Trim();
				if (newLine.Length > 0)
					payload += newLine + "\n";
			}
			payload = payload.TrimEnd();

			byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
			byte[] payloadHash;
			using (SHA512 shaM = new SHA512Managed())
			{
				payloadHash = shaM.ComputeHash(payloadBytes);
			}

			byte[] signedHash;
			using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
			{
				rsa.FromXmlString(File.ReadAllText(privateKeyPath));
				signedHash = rsa.SignData(payloadHash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
			}

			string finalPayloadHash = Convert.ToBase64String(signedHash);

			vifLines[0] = vifLines[0] + finalPayloadHash;

			File.Delete(sourcePath);
			File.WriteAllLines(sourcePath, vifLines, Encoding.UTF8);
			File.WriteAllText(sourcePath, File.ReadAllText(sourcePath, Encoding.UTF8).TrimEnd(), Encoding.UTF8); //To remove the trailing newline on the end of the file
		}

		/// <summary>
		/// GZips the file at <paramref name="sourcePath"/> and writes the result to a path that it then returns.
		/// </summary>
		/// <param name="sourcePath">The filepath of the source file.</param>
		/// <returns>The path of the GZipped file, which is <paramref name="sourcePath"/> + '.gz'.</returns>
		private static string GZipFile(string sourcePath)
		{
			FileInfo fileToBeGZipped = new FileInfo(sourcePath);
			FileInfo gzipFileName = new FileInfo(fileToBeGZipped.FullName + ".gz");

			using (FileStream fileToBeZippedAsStream = fileToBeGZipped.OpenRead())
			{
				using (FileStream gzipTargetAsStream = gzipFileName.Create())
				{
					using (GZipStream gzipStream = new GZipStream(gzipTargetAsStream, CompressionMode.Compress))
					{
						fileToBeZippedAsStream.CopyTo(gzipStream);
					}
				}
			}

			return gzipFileName.FullName;
		}
	}
}
