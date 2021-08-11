using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices;

/*
 * Authenticates to LDAP using the provided username and password, searches for a target account, and sets the target account to never expire.
 * Usage: LDAPChangeAccountExpiration.exe auth_username auth_password target_account new_password
 * Example: LDAPChangeAccountExpiration.exe Alice Summer2020 JoeTarget 
 * 
 * Note: This is designed to be run on a domain-joined system and identifies the domain controller+LDAP server via Environment.UserDomainName. Modify this if targeting a different host.
 * 
 * @ac3lives, 2021
 */
namespace LdapChangeAccountExpiration
{
    class Program
    {
        static void Main(string[] args)
        {
            //arg[0] = Username to authenticate to LDAP with
            //arg[1] = password to authenticate to LDAP with
            //arg[2] = Username to disable account expiration for
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
                    Console.WriteLine("Found user: {0}", Convert.ToString(AdObj.Properties["sAMAccountName"][0]));
                    Console.WriteLine("Setting user accountExpiration to 0 (never expires)");
                    DirectoryEntry user = AdObj.GetDirectoryEntry();
                    user.Properties["accountExpires"].Value = 0;
                    user.CommitChanges();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                    Console.WriteLine("StackTrace: {0}", e.StackTrace);
                    Console.WriteLine("TargetSite: {0}", e.TargetSite);
                }

            }
        }
    }
}
