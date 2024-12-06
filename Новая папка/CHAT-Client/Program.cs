using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CHAT_Client
{
    internal class Program
    {
        private static bool VerifyServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var hash = certificate.GetCertHashString();
            if (hash == "A52C43D7DB126B69DEA14CE6C6260FF0A1C951EF")
            {
                Console.WriteLine($"[+] Accepted server certificate with hash {hash}");
                return true;
            }

            Console.WriteLine($"[-] Unknown server certificate, rejecting.\r\n" +
                $"    Hash: {hash}\r\n" +
                $"    Subject: {certificate.Subject}\r\n" +
                $"    Issuer: {certificate.Issuer}");

            return false;
        }

        static void Main(string[] args)
        {
            string serverAddress = "127.0.0.1";
            int serverPort = 443;

            try
            {
                var tcpClient = new TcpClient(serverAddress, serverPort);

                var sslStream = new SslStream(tcpClient.GetStream(), false,
                    new RemoteCertificateValidationCallback(VerifyServerCertificate));

                // we dont send any certificates as we dont perform mutual authentication
                sslStream.AuthenticateAsClient(serverAddress, new X509CertificateCollection(),
                    System.Security.Authentication.SslProtocols.Tls12, false);

                Console.WriteLine($"[+] Connected to {tcpClient.Client.RemoteEndPoint}");

                byte[] buffer = new byte[2048];
                AsyncCallback readCallback = null;
                sslStream.BeginRead(buffer, 0, buffer.Length, readCallback = (ar) => {
                    try
                    {
                        var bytesRead = sslStream.EndRead(ar);
                        var response = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        Console.Write(response);

                        // using Task to avoid stack overflow from recursive calling
                        Task.Run(() =>
                            sslStream.BeginRead(buffer, 0, buffer.Length, readCallback, null));
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Error reading from stream: {ex.Message}");
                        sslStream.Dispose();
                        tcpClient.Dispose();
                    }
                }, null);

                Console.CancelKeyPress += (o,e) => {
                    sslStream.Dispose();
                    tcpClient.Dispose();
                };

                while (true)
                {
                    var strMessage = Console.ReadLine() + "\r\n"; // ReadLine() returns string without new line
                    var byteMessage = Encoding.UTF8.GetBytes(strMessage);
                    sslStream.Write(byteMessage);
                    sslStream.Flush();
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }

    }
}
