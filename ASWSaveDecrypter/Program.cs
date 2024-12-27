// See https://aka.ms/new-console-template for more information

using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using AesProvider = System.Security.Cryptography.Aes;

if (args.Length < 3)
{
    Console.WriteLine("Usage:" +
                      "ASWSaveDecrypter <key> <inputFile> <outputFile>");
    return;
}

const int blockSize = 16 * 8;

var provider = AesProvider.Create();
provider.Mode = CipherMode.ECB;
provider.Padding = PaddingMode.None;
provider.BlockSize = blockSize;

var key = Encoding.ASCII.GetBytes(args[0]).Take(32).ToArray();

var file = File.ReadAllBytes(args[1]);

var decrypt = provider.CreateDecryptor(key, null).TransformFinalBlock(file, 0, file.Length);
using var ds = new ZLibStream(new MemoryStream(decrypt), CompressionMode.Decompress);
using var sr = new BinaryReader(ds);
const int bufferSize = 4096;
using var ms = new MemoryStream();
var buffer = new byte[bufferSize];
int count;
while ((count = sr.Read(buffer, 0, buffer.Length)) != 0)
    ms.Write(buffer, 0, count);

var buf = ms.ToArray();

var final = provider.CreateDecryptor(key, null).TransformFinalBlock(buf, 0, buf.Length);

File.WriteAllBytes(args[2], final);