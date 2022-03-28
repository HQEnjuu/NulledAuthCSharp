using System;
using System.IO;
using System.Management;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;

namespace NulledAuthCSharp
{
    class AuthHandler
    {
        private string AuthKey;
        private string hwid;
        private string programId;
        private int minumumGroup;
        private string secretKey;

        private string response;
        private int statusCode = 418;

        public class Data
        {
            public string hash { get; set; }
            public string mid { get; set; }
            public string name { get; set; }
            public string Likes { get; set; }
            public List<string> groups { get; set; }
            public string extra { get; set; }
            public string message { get; set; }
        }

        public class AuthData
        {
            public bool status { get; set; }
            public Data data { get; set; }
        }

        private AuthData authData;
        private Usergroup[] groups;

        public AuthHandler(string AuthKey, string programId, int minimumGroup, string secretKey)
        {
            this.AuthKey = AuthKey;
            this.hwid = this.getHwid();
            this.programId = programId;
            this.minumumGroup = minimumGroup;
            this.secretKey = secretKey;
        }

        public AuthData getAuthData()
        {
            return authData;
        }

        private bool hasPermissions()
        {
            int permissionLevel = getPermissionLevel();
            return permissionLevel >= minumumGroup;
        }

        private int getPermissionLevel()
        {
            switch (authData.data.extra)
            {
                case "1337": return 2;
                case "1338": return 3;
            }
            long epoch = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            if (Convert.ToInt64(authData.data.extra) > epoch)
            {
                return 1;
            } 
            else
            {
                authData.status = false;
            }

            return 0;
        }

        private string getHash()
        {
            return authData.data.hash;
        }

        private string calculateHash()
        {
            string epoch = Convert.ToString(Math.Round((DateTimeOffset.Now.ToUnixTimeMilliseconds() / 1000.0) / 200) * 200);

            string[] genId = new string[] { secretKey, AuthKey, hwid, epoch };

            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    string message = "";

                    foreach (string data in genId)
                    {
                        message = message + data;
                    }

                    byte[] digest = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));

                    return BitConverter.ToString(digest).Replace("-", "");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "";
            }
        }

        public bool canAuth()
        {
            if (authData.status)
            {
                authData.status = hasPermissions();
            }

            if (calculateHash() != getHash()) // I actually don't know if that works or not...
            {
                authData.status = false;
            }

            return authData.status;
        }        

        public bool checkReg()
        {
            return doAuthRequest("register");
        }

        public bool checkAuth()
        {
            return doAuthRequest("validate");
        }

        private bool doAuthRequest(String action)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://www.nulled.to/authkeys.php");
                request.Proxy = null;
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.UserAgent = "NulledAuthCSharp/1.0";
                var postData = Encoding.UTF8.GetBytes(action + "=1&key=" + AuthKey + "&hwid=" + hwid + "&program_id=" + programId);

                using (var stream = request.GetRequestStream())
                {
                    stream.Write(postData, 0, postData.Length);
                }

                var responsedata = (HttpWebResponse)request.GetResponse();        

                response = new StreamReader(responsedata.GetResponseStream()).ReadToEnd();
                statusCode = (int)responsedata.StatusCode;

                if (action == "validate")
                {
                    authData = JsonConvert.DeserializeObject<AuthData>(response);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        private string getUuid()
        {
            ManagementObjectSearcher mos = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject obj in mos.Get())
            {
                return obj.Properties["UUID"].Value.ToString();
            }
            return null;
        }

        private string getmGuid()
        {
            return Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography").GetValue("MachineGuid").ToString().ToUpper();
        }

        private string getHwid()
        {
            string cName = Environment.MachineName;
            string uName = Environment.UserName;
            string pRev = Environment.GetEnvironmentVariable("PROCESSOR_REVISION");
            string tSpace = new DriveInfo(@"C:").TotalSize.ToString();
            string uuid = getUuid();
            string mguid = getmGuid();

            string[] genId = new string[] {cName, uName, pRev, tSpace, uuid, mguid};

            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    string message = "";

                    foreach (string data in genId)
                    {
                        message = message + data;
                    }

                    byte[] digest = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));

                    return BitConverter.ToString(digest).Replace("-", "");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "";
            }
        }

        public string getResponse()
        {
            return response;
        }

        public int getStatusCode()
        {
            return statusCode;
        }

        public bool getRequestStatus()
        {
            return authData.status;
        }

        public string getUsername()
        {
            return authData.data.name;
        }

        public string getUserId()
        {
            return authData.data.mid;
        }

        public string getUserLikes()
        {
            return authData.data.Likes;
        }

        public AuthData getAuthResponse()
        {
            return authData;
        }
    }
}
