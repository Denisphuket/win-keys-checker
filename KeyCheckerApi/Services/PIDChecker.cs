// PIDChecker.cs
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
                throw; // Re-throw the exception to be handled by the caller
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
        // URL веб-сервиса активации
        const string url = "https://activation.sls.microsoft.com/BatchActivation/BatchActivation.asmx";

        try
        {
            // Создание клиента HTTP
            using (HttpClient httpClient = new HttpClient())
            {
                // Установка таймаута для HttpClient
                httpClient.Timeout = TimeSpan.FromMinutes(1);

                // Подготовка SOAP запроса
                var soapRequest = PrepareSoapRequest(pid);

                // Создание HttpRequestMessage
                using (var httpRequest = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    httpRequest.Content = new StringContent(soapRequest, Encoding.UTF8, "text/xml");
                    httpRequest.Headers.Add("SOAPAction", "http://www.microsoft.com/BatchActivationService/BatchActivate");

                    // Отправка запроса и получение ответа
                    var response = await httpClient.SendAsync(httpRequest);

                    // Проверка статуса HTTP ответа
                    if (!response.IsSuccessStatusCode)
                    {
                        return $"Error: {response.StatusCode}";
                    }

                    // Чтение ответа
                    var soapResponse = await response.Content.ReadAsStringAsync();

                    // Обработка SOAP ответа
                    // var activationsRemaining = ParseSoapResponse(soapResponse);
                    // return activationsRemaining;
                    return soapResponse;
                }
            }
        }
        catch (WebException webEx)
        {
            // Обработка исключений сетевых ошибок
            return $"WebException: {webEx.Message}";
        }
        catch (Exception ex)
        {
            // Обработка других видов исключений
            return $"Exception: {ex.Message}";
        }
    }

    private static string PrepareSoapRequest(string pid)
    {
        // Microsoft's PRIVATE KEY for HMAC-SHA256 encoding
        byte[] bPrivateKey = new byte[] 
            { 
                0xfe, 0x31, 0x98, 0x75, 0xfb, 0x48, 0x84, 0x86, 0x9c, 0xf3, 0xf1, 0xce, 0x99, 0xa8, 0x90, 0x64, 
                0xab, 0x57, 0x1f, 0xca, 0x47, 0x04, 0x50, 0x58, 0x30, 0x24, 0xe2, 0x14, 0x62, 0x87, 0x79, 0xa0
            };

        // XML Namespace
        const string uri = "http://www.microsoft.com/DRM/SL/BatchActivationRequest/1.0";

        // Создание нового XML документа
        XmlDocument xmlDoc = new XmlDocument();

        // Создание корневого элемента
        XmlElement rootElement = xmlDoc.CreateElement("ActivationRequest", uri);
        xmlDoc.AppendChild(rootElement);

        // Создание элемента VersionNumber
        XmlElement versionNumber = xmlDoc.CreateElement("VersionNumber", uri);
        versionNumber.InnerText = "2.0";
        rootElement.AppendChild(versionNumber);

        // Создание элемента RequestType
        XmlElement requestType = xmlDoc.CreateElement("RequestType", uri);
        requestType.InnerText = "2";
        rootElement.AppendChild(requestType);

        // Создание элемента Requests Group
        XmlElement requestsGroupElement = xmlDoc.CreateElement("Requests", uri);

        // Создание элемента Request
        XmlElement requestElement = xmlDoc.CreateElement("Request", uri);

        // Добавление PID в элемент Request
        XmlElement pidEntry = xmlDoc.CreateElement("PID", uri);
        pidEntry.InnerText = pid.Replace("XXXXX", "55041");
        requestElement.AppendChild(pidEntry);

        // Добавление элемента Request в элемент Requests Group
        requestsGroupElement.AppendChild(requestElement);

        // Добавление элементов Requests и Request в XML документ
        rootElement.AppendChild(requestsGroupElement);

        // Получение массива байтов XML документа в Unicode
        byte[] byteXml = Encoding.Unicode.GetBytes(xmlDoc.InnerXml);

        // Конвертация массива байтов в Base64
        string base64Xml = Convert.ToBase64String(byteXml);

        // Вычисление Digest для Base64 XML байтов
        string digest;
        using (HMACSHA256 hmacsha256 = new HMACSHA256(bPrivateKey))
        {
            digest = Convert.ToBase64String(hmacsha256.ComputeHash(byteXml));
        }

        // Создание SOAP-обертки для веб-запроса
        string soapEnvelope = $"<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><BatchActivate xmlns=\"http://www.microsoft.com/BatchActivationService\"><request><Digest>{digest}</Digest><RequestXml>{base64Xml}</RequestXml></request></BatchActivate></soap:Body></soap:Envelope>";

        return soapEnvelope;
    }

    private static string ParseSoapResponse(string soapResponse)
    {
        // Парсинг SOAP ответа
        using (XmlReader reader = XmlReader.Create(new StringReader(soapResponse)))
        {
            // Чтение значения ResponseXML
            reader.ReadToFollowing("ResponseXml");
            string responseXml = reader.ReadElementContentAsString();

            // Удаление HTML Entities из ResponseXML
            responseXml = responseXml.Replace("&gt;", ">");
            responseXml = responseXml.Replace("&lt;", "<");

            // Изменение значения кодировки в ResponseXML
            responseXml = responseXml.Replace("utf-16", "utf-8");

            // Чтение исправленного значения ResponseXML как XML
            using (XmlReader responseReader = XmlReader.Create(new StringReader(responseXml)))
            {
                responseReader.ReadToFollowing("ActivationRemaining");
                string count = responseReader.ReadElementContentAsString();

                if (int.TryParse(count, out int remaining) && remaining < 0)
                {
                    responseReader.ReadToFollowing("ErrorCode");
                    string error = responseReader.ReadElementContentAsString();

                    if (error == "0x67")
                    {
                        return "0 (Blocked)";
                    }
                }

                return count;
            }
        }
    }

    private static byte[] StringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Строка не содержит валидное шестнадцатеричное значение. Длина строки должна быть четной.");

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }




        
    
    }
}
