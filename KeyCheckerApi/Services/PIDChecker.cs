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

                Console.WriteLine($"pkeyConfigList: {pkeyConfigList}");

                foreach (var config in pkeyConfigList)
                {
                    Console.WriteLine($"config: {config}");
                    pKeyConfig = config;
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
                        detail.Cid = Convert.ToInt32(detail.Eid.Substring(6, 5)).ToString(CultureInfo.InvariantCulture);
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

        public static async Task<string> GetRemainingActivationsAsync(string pid)
        {
            const string url = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx";

            try
            {
                using (HttpClient httpClient = new HttpClient())
                {
                    httpClient.Timeout = TimeSpan.FromMinutes(1);

                    var soapRequest = PrepareSoapRequest(pid);

                    using (var httpRequest = new HttpRequestMessage(HttpMethod.Post, url))
                    {
                        httpRequest.Content = new StringContent(soapRequest, Encoding.UTF8, "text/xml");
                        httpRequest.Headers.Add("SOAPAction", "http://www.microsoft.com/BatchActivationService/BatchActivate");

                        var response = await httpClient.SendAsync(httpRequest);

                        if (!response.IsSuccessStatusCode)
                        {
                            return $"Error: {response.StatusCode}";
                        }

                        var soapResponse = await response.Content.ReadAsStringAsync();
                        return soapResponse;
                    }
                }
            }
            catch (WebException webEx)
            {
                return $"WebException: {webEx.Message}";
            }
            catch (Exception ex)
            {
                return $"Exception: {ex.Message}";
            }
        }

        private static string PrepareSoapRequest(string pid)
        {
            return $@"<?xml version=""1.0"" encoding=""utf-8""?>
                <soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
                               xmlns:xsd=""http://www.w3.org/2001/XMLSchema""
                               xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
                  <soap:Body>
                    <BatchActivate xmlns=""http://www.microsoft.com/BatchActivationService"">
                      <request>
                        <Version>2.0</Version>
                        <Requests>
                          <Request>
                            <PID>{pid}</PID>
                            <Type>5</Type>
                            <IsConfirmation>false</IsConfirmation>
                          </Request>
                        </Requests>
                      </request>
                    </BatchActivate>
                  </soap:Body>
                </soap:Envelope>";
        }
    }
}
