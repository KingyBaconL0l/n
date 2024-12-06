using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.IO;
using System.Net.Http;

namespace CHAT_Server
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var certificatePassword = "certPasswd";
            // loading certificate from memory, as we want server to be single executable without dependencies
            var certificate = new X509Certificate2(Resources.cert, certificatePassword);

            var listener = new TcpListener(IPAddress.Loopback, 443);
            listener.Start();
            Console.WriteLine($"[*] Listening for connection on {listener.LocalEndpoint}");

            var tcpClient = listener.AcceptTcpClient();
            Console.WriteLine($"[+] {tcpClient.Client.RemoteEndPoint} connected.");

            // we dont support multiple clients, so there's no need in keeping to listen for clients
            listener.Stop();

            var sslStream = new SslStream(tcpClient.GetStream(), false,
                new RemoteCertificateValidationCallback(
                    (sender, receivedCertificate, chain, sslPolicyErrors) => true // we don't perform mutual authentication, so skip verification of client's cert
            )); 

            try
            {
                sslStream.AuthenticateAsServer(certificate, false, System.Security.Authentication.SslProtocols.Tls12, true);

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

                Console.CancelKeyPress += (o, e) => {
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
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
    }
}
