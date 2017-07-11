using System;
using System.Diagnostics;
using System.Management;
using System.Security.Cryptography.X509Certificates;

namespace processWatcher
{
    class Program
    {
        static void Main()
        {
            Console.Title = "Process Watcher";

            ManagementEventWatcher start_watch = new ManagementEventWatcher
              (new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            ManagementEventWatcher stop_watch = new ManagementEventWatcher
              (new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));

            start_watch.EventArrived += new EventArrivedEventHandler(startWatch_EventArrived);
            start_watch.Start();

            stop_watch.EventArrived += new EventArrivedEventHandler(stopWatch_EventArrived);
            stop_watch.Start();

            Console.WriteLine("press esc key for exit");
            
            do
            {
                while (!Console.KeyAvailable)
                {
                    System.Threading.Thread.Sleep(50);
                    
                }
            } while (Console.ReadKey(true).Key != ConsoleKey.Escape);

            start_watch.Stop();
            stop_watch.Stop();
        }
        static void startWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                string path = processPath(int.Parse(e.NewEvent.Properties["ProcessID"].Value.ToString()));

                Console.WriteLine("Process Started:");

                Console.WriteLine("ProcessID:" + e.NewEvent.Properties["ProcessID"].Value);
                Console.WriteLine("ProcessPath:" + path);
                Console.WriteLine("ProcessCert:" + checkSignature(path));

                Console.WriteLine("================================================================================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Err:" + ex.Data);

                Console.WriteLine("Process Started:");
                Console.WriteLine("ProcessID:" + e.NewEvent.Properties["ProcessID"].Value);
                Console.WriteLine("ProcessName:" + e.NewEvent.Properties["ProcessName"].Value);

                Console.WriteLine("================================================================================================");
            }
        }

        static void stopWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                Console.WriteLine("Process Stopped:");

                Console.WriteLine("ProcessID:" + e.NewEvent.Properties["ProcessID"].Value);
                Console.WriteLine("ProcessName:" + e.NewEvent.Properties["ProcessName"].Value);

                Console.WriteLine("================================================================================================");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Err:" + ex.Data);

                Console.WriteLine("================================================================================================");
            }
        }

        static string processPath(int pid)
        {
            Process p = Process.GetProcessById(pid);
            return p.MainModule.FileName;
        }

        static bool checkSignature(string fileName)
        {
            X509Chain cert_chain = new X509Chain();
            X509Certificate2 cert = default(X509Certificate2);
            bool is_chain_valid = false;
            try
            {
                X509Certificate signer = X509Certificate.CreateFromSignedFile(fileName);
                cert = new X509Certificate2(signer);
            }
            catch
            {
                return is_chain_valid;
            }

            cert_chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            cert_chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            cert_chain.ChainPolicy.UrlRetrieval‎Timeout = new TimeSpan(0, 1, 0);
            cert_chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            is_chain_valid = cert_chain.Build(cert);

            if (is_chain_valid)
            {
                return is_chain_valid;
            }
            else
            {
                return is_chain_valid;
            }
        }
    }
}
