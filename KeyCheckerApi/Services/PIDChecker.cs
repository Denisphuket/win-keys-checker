using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml;
using System.IO;
using System.Collections.Generic;
using System.Globalization;
using KeyCheckerApi.Models;
using System.Security.Cryptography;
using System.Net;
using System.Threading.Tasks;

namespace KeyCheckerApi.Services
{
    public static class PIDChecker
    {

        [DllImport("pidgenx.dll", EntryPoint = "PidGenX", CharSet = CharSet.Auto)]
        private static extern int PidGenX(
            string ProductKey,
            string PkeyPath,
            string MSPID,
            int UnknownUsage,
            IntPtr ProductID,
            IntPtr DigitalProductID,
            IntPtr DigitalProductID4);

        private static List<string> pkeyConfigList;

        static PIDChecker()
        {
            try
            {
                pkeyConfigList = GetPKeyConfigList();
                Console.WriteLine($"pkeyConfigList: {pkeyConfigList}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error initializing pkeyConfigList: {ex.Message}");
            }
        }

        private static List<string> GetPKeyConfigList()
        {
            var pkeyConfigList = new List<string>();
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.Load("PKeyConfig/PkeyData.xml");

                var configNodeList = xmlDoc.GetElementsByTagName("configType");
                foreach (XmlNode node in configNodeList)
                {
                    pkeyConfigList.Add("PKeyConfig/" + node.Attributes["configPath"].Value);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading PKeyConfig list: {ex.Message}");
                throw;
            }

            return pkeyConfigList;
        }

        public static KeyDetail Check(string productKey)
        {
            IntPtr PID = IntPtr.Zero;
            IntPtr DPID = IntPtr.Zero;
            IntPtr DPID4 = IntPtr.Zero;

            try
            {
                var detail = new KeyDetail(productKey);

                var gpid = new byte[0x32];
                var opid = new byte[0xA4];
                var npid = new byte[0x04F8];

                PID = Marshal.AllocHGlobal(0x32);
                DPID = Marshal.AllocHGlobal(0xA4);
                DPID4 = Marshal.AllocHGlobal(0x04F8);

                var MSPID = "00000";

                gpid[0] = 0x32;
                opid[0] = 0xA4;
                npid[0] = 0xF8;
                npid[1] = 0x04;

                Marshal.Copy(gpid, 0, PID, 0x32);
                Marshal.Copy(opid, 0, DPID, 0xA4);
                Marshal.Copy(npid, 0, DPID4, 0x04F8);

                var RetID = -1;
                string pKeyConfig = "";



                foreach (var config in pkeyConfigList)
                {
//                     Console.WriteLine($"config: {config}");
                    pKeyConfig = config;
                    Console.WriteLine($"DPID: {DPID}");
                    Console.WriteLine($"DPID4: {DPID4}");
                    Console.WriteLine($"MSPID: {MSPID}");
                    RetID = PidGenX(productKey, pKeyConfig, MSPID, 0, PID, DPID, DPID4);
                    if (RetID == 0)
                    {
                        Marshal.Copy(PID, gpid, 0, gpid.Length);
                        Marshal.Copy(DPID4, npid, 0, npid.Length);

                        detail.KeyPid = GetString(gpid, 0);
                        detail.Eid = GetString(npid, 8);
                        detail.Aid = GetString(npid, 136);
                        detail.Edi = GetString(npid, 280);
                        detail.Sub = GetString(npid, 888);
                        detail.Lit = GetString(npid, 1016);
                        detail.Lic = GetString(npid, 1144);
                        detail.msft2009 = GetString(npid, 1713);
                        detail.msft20091 = GetString(npid, 1714);
                        detail.Cid = Convert.ToInt32(detail.Eid.Substring(6, 5)).ToString(CultureInfo.InvariantCulture);

                        Console.WriteLine($"detail.KeyPid: {detail.KeyPid}");
                        Console.WriteLine($"detail.Eid: {detail.Eid}");
                        Console.WriteLine($"detail.Aid: {detail.Aid}");
                        Console.WriteLine($"detail.Edi: {detail.Edi}");
                        Console.WriteLine($"detail.Sub: {detail.Sub}");
                        Console.WriteLine($"detail.Lic: {detail.Lic}");
                        Console.WriteLine($"detail.Cid: {detail.Cid}");
                        Console.WriteLine($"pKeyConfig: {pKeyConfig}");
                        Console.WriteLine($"detail.msft2009: {detail.msft2009}");
                        Console.WriteLine($"detail.msft20091: {detail.msft20091}");
                        Console.WriteLine($"detail: {detail}");

                        var prd = GetProductDescription(pKeyConfig, "{" + detail.Aid + "}", detail.Edi);

                        if (prd.StartsWith("RTM_"))
                        {
                            prd = "Office14" + prd.Remove(0, 4);
                        }
                        detail.Prd = prd;

                        break;
                    }
                }

                return detail;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking product key: {ex.Message}");
                return null;
            }
            finally
            {
                if (PID != IntPtr.Zero) Marshal.FreeHGlobal(PID);
                if (DPID != IntPtr.Zero) Marshal.FreeHGlobal(DPID);
                if (DPID4 != IntPtr.Zero) Marshal.FreeHGlobal(DPID4);
            }
        }

        private static string GetString(byte[] bytes, int index)
        {
            var n = index;
            while (!(bytes[n] == 0 && bytes[n + 1] == 0)) n++;
            return Encoding.ASCII.GetString(bytes, index, n - index).Replace("\0", "");
        }

        private static string GetProductDescription(string pkey, string aid, string edi)
        {
            try
            {
                var doc = new XmlDocument();
                doc.Load(pkey);
                using (var stream = new MemoryStream(Convert.FromBase64String(doc.GetElementsByTagName("tm:infoBin")[0].InnerText)))
                {
                    doc.Load(stream);
                    var ns = new XmlNamespaceManager(doc.NameTable);
                    ns.AddNamespace("pkc", "http://schemas.microsoft.com/DRM/PKEY/Configuration/2.0");
                    var node = doc.SelectSingleNode($"/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='{aid}']", ns)
                            ?? doc.SelectSingleNode($"/pkc:ProductKeyConfiguration/pkc:Configurations/pkc:Configuration[pkc:ActConfigId='{aid.ToUpper()}']", ns);

                    if (node != null && node["EditionId"].InnerText.Contains(edi))
                    {
                        return node["ProductDescription"].InnerText;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting product description: {ex.Message}");
            }
            return "Not Found";
        }

    }
}
