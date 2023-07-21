using Newtonsoft.Json;
using NLog;
using NLog.Targets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;

class getIOC2TA
{
    private static readonly NLog.Logger log = NLog.LogManager.GetCurrentClassLogger();
    private static string host = "https://api.intelligence.mandiant.com";
    private static string path = "/token";
    private static string ConfigurationFile = Directory.GetCurrentDirectory() + "\\MandiantAdvantage.ini";
    private static string XAppName = "getioc2ta.dh3c.v1.0";

    static void Main(string[] args)
    {
        var logfile = new FileTarget("logfile")
        {
            FileName = "${basedir}/getIOC2TA.log",
            Layout = "${longdate}|${level:uppercase=true}|getIOC2TA - ${message:withexception=true}"
        };
        var console = new ColoredConsoleTarget()
        {
            UseDefaultRowHighlightingRules = true,
            Layout = "${longdate}|${level:uppercase=true}|getIOC2TA - ${message:withexception=true}"
        };

        NLog.LogManager.Setup().LoadConfiguration(builder => {
            builder.ForLogger().FilterMinLevel(LogLevel.Info).Targets.Add(console);
            builder.ForLogger().FilterMinLevel(LogLevel.Debug).Targets.Add(logfile);
        });

        if (args.Length == 0)
        {
            log.Error("Invalid command. Please use 'run' or 'create_config' as the first argument.");
            return;
        }

        if (args[0] == "run")
        {
            Run(args);
        }
        else if (args[0] == "create_config")
        {
            if (args.Length != 3)
            {
                log.Info("Please provide both the API Key and API Secret. Eg. getIOC2TA create_config <apiKey> <apiSecret>");
                return;
            }

            string apiKey = args[1];
            string apiSecret = args[2];
            string encodedAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes(apiKey + ":" + apiSecret));
            CreateConfig(encodedAuth);
        }
        else
        {
            log.Error("Invalid command. Please use 'run' or 'create_config' as the first argument.");
        }
    }

    static void Run(string[] args)
    {
        if (CheckTokenExpiry())
        {
            GetNewToken();
        }

        string token = GetTokenFromConfig();
        if (string.IsNullOrEmpty(token))
        {
            log.Error("Token not found. Please run 'create_config' first.");
            return;
        }

        try
        {
            if (!File.Exists("ip.lst"))
            {
                log.Error("ip.lst not found!");
                return;
            }

            List<string> listFinal = new List<string>();

            int lineCount = File.ReadLines(@"ip.lst").Count();
            File.WriteAllText("ip.csv", "IP_Address,M_Score,MTA_Attribution,MTA_Country,M_Intel_Quality\n");

            using (StreamReader reader = new StreamReader("ip.lst"))
            {
                string line;
                double lc = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    lc = lc + 1;
                    log.Info("Getting info for " + line + "... " + (lc / lineCount).ToString("0%"));
                    string url = host + "/v4/indicator/ipv4/" + line.Trim();
                    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                    request.Method = "GET";
                    request.Headers["Authorization"] = "Bearer " + token;
                    request.ContentType = "application/x-www-form-urlencoded";
                    request.Accept = "application/json";
                    request.Headers["X-App-Name"] = XAppName;

                    string taId = string.Empty;
                    string taName = string.Empty;
                    string taCountry = string.Empty;
                    string mScore = string.Empty;

                    try {
                       
                        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                        using (StreamReader streamReader = new StreamReader(response.GetResponseStream()))
                        {
                            string responseJson = streamReader.ReadToEnd();
                            dynamic jsonData = JsonConvert.DeserializeObject<dynamic>(responseJson);
                           

                            if (jsonData["attributed_associations"] != null)
                            {
                                taId = jsonData["attributed_associations"][0]["id"];
                                taName = jsonData["attributed_associations"][0]["name"];
                                mScore = jsonData["mscore"]?.ToString() ?? "";
                            } else
                            {
                                //taId = jsonData["id"];
                                mScore = jsonData["mscore"];

                            }

                            if (!string.IsNullOrEmpty(taId))
                            {
                                string taUrl = host + "/v4/actor/" + taId;
                                HttpWebRequest taRequest = (HttpWebRequest)WebRequest.Create(taUrl);
                                taRequest.Method = "GET";
                                taRequest.Headers["Authorization"] = "Bearer " + token;
                                taRequest.ContentType = "application/x-www-form-urlencoded";
                                taRequest.Accept = "application/json";
                                taRequest.Headers["X-App-Name"] = XAppName;

                                HttpWebResponse taResponse = (HttpWebResponse)taRequest.GetResponse();
                                using (StreamReader taStreamReader = new StreamReader(taResponse.GetResponseStream()))
                                {
                                    string taResponseJson = taStreamReader.ReadToEnd();
                                    dynamic taJsonData = JsonConvert.DeserializeObject<dynamic>(taResponseJson);
                                    if (taJsonData["locations"] != null)
                                    {
                                        taCountry = taJsonData["locations"]["source"][0]["country"]["name"];
                                    }
                                }
                            }
                            //listFinal.Add($"{line.Trim()},{mScore},{taName},{taCountry},");
                            //sequential write
                            File.AppendAllText("ip.csv", $"{line.Trim()},{mScore},{taName},{taCountry},\n");
                        }
                       
                    } catch (WebException e) {
                            if(e.Message.Contains("404")) { //listFinal.Add($"{line.Trim()},{mScore},{taName},{taCountry},");
                                                            File.AppendAllText("ip.csv", $"{line.Trim()},{mScore},{taName},{taCountry},\n"); } 
                                                            else { log.Error(e.Message); }
                    }

                   
                        System.Threading.Thread.Sleep(2000); // Wait for 2 seconds before the next request
                    }
                }
            //listFinal.Insert(0, "IP Address,MANDIANT SCORE,MANDIANT ACTOR ATTRIBUTION,MANDIANT THREAT ACTOR COUNTRY,MANDIANT INTEL SOURCE QUALITY");
           // File.WriteAllLines("ip.csv", listFinal);
            log.Info("Finished!");
        }
        catch (Exception e)
        {
            log.Error($"Error making call: {e.Message}");
        }
    }

    static void GetNewToken()
    {
        string auth = GetAuthorizationFromConfig();
        if (string.IsNullOrEmpty(auth))
        {
            log.Info("Configuration file not found. Please run create_config first.");
            return;
        }

        try
        {
            log.Info("Getting new token...");
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("X-App-Name", XAppName);

                var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            });

                HttpResponseMessage response = client.PostAsync(host + path, content).Result;
                string responseJson = response.Content.ReadAsStringAsync().Result;
                dynamic jsonData = JsonConvert.DeserializeObject<dynamic>(responseJson);
                string token = jsonData["access_token"]?.ToString() ?? "";
                int expiresIn = jsonData["expires_in"];
                DateTime currentDateTime = DateTime.Now;
                DateTime expiresDateTime = currentDateTime.AddSeconds(expiresIn);
                string expiresTime = expiresDateTime.ToString("yyyy-MM-dd HH:mm:ss");

                UpdateTokenInConfig(token, expiresTime);
                log.Info($"Refreshed token in {ConfigurationFile}");
            }
        }
        catch (WebException e)
        {
            log.Error($"Error while getting new token: {e.Message}");
        }
    }

    static bool CheckTokenExpiry()
    {
        log.Info("Checking token validity...");
        string expiresTime = GetExpiresTimeFromConfig();
        if (string.IsNullOrEmpty(expiresTime))
        {
            log.Info("Configuration file not found. Please run create_config first.");
            return true; // Assume token expired if the configuration is not available.
        }

        DateTime currentDate = DateTime.Now;
        DateTime expectedDate = DateTime.ParseExact(expiresTime, "yyyy-MM-dd HH:mm:ss", null);

        return currentDate > expectedDate;
    }

    static void CreateConfig(string auth)
    {
        try
        {
            using (StreamWriter writer = new StreamWriter(ConfigurationFile))
            {
                writer.WriteLine("[Mandiant_Advantage_API]");
                writer.WriteLine($"auth={auth}");
                writer.WriteLine("token=");
                writer.WriteLine("expires_time=1970-01-01 00:00:00");
                
            }
            log.Info($"Configuration file has been created {ConfigurationFile}");
        }
        catch (Exception e)
        {
            log.Error($"Error creating config file: {e.Message}");
        }
    }

    static string GetAuthorizationFromConfig()
    {
        if (File.Exists(ConfigurationFile))
        {
            try
            {
                using (StreamReader reader = new StreamReader(ConfigurationFile))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("auth="))
                        {
                            return line.Substring("auth=".Length);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                log.Error($"Error reading configuration file: {e.Message}");
            }
        }

        return string.Empty;
    }

    static string GetTokenFromConfig()
    {
        if (File.Exists(ConfigurationFile))
        {
            try
            {
                using (StreamReader reader = new StreamReader(ConfigurationFile))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("token="))
                        {
                            return line.Substring("token=".Length);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                log.Error($"Error reading configuration file: {e.Message}");
            }
        }

        return string.Empty;
    }

    static string GetExpiresTimeFromConfig()
    {
        if (File.Exists(ConfigurationFile))
        {
            try
            {
                using (StreamReader reader = new StreamReader(ConfigurationFile))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("expires_time="))
                        {
                            return line.Substring("expires_time=".Length);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                log.Error($"Error reading configuration file: {e.Message}");
            }
        }

        return string.Empty;
    }

    static void UpdateTokenInConfig(string token, string expiresTime)
    {
        try
        {
            List<string> lines = new List<string>();
            if (File.Exists(ConfigurationFile))
            {
                using (StreamReader reader = new StreamReader(ConfigurationFile))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("token="))
                        {
                            lines.Add("token=" + token);
                        }
                        else if (line.StartsWith("expires_time="))
                        {
                            lines.Add("expires_time=" + expiresTime);
                        }
                        else
                        {
                            lines.Add(line);
                        }
                    }
                }
            }

            File.WriteAllLines(ConfigurationFile, lines);
        }
        catch (Exception e)
        {
            log.Error($"Error updating configuration file: {e.Message}");
        }
    }
}
