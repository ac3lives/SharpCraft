using System;
using System.Runtime.InteropServices ;
using System.Threading;

namespace MountShare
{
	#Credits to example from http://lookfwd.doitforme.gr/blog/media/PinvokeWindowsNetworking.cs
	public class PinvokeWindowsNetworking
	{
		
		#region Consts
		const int RESOURCE_CONNECTED = 0x00000001;
		const int RESOURCE_GLOBALNET = 0x00000002;
		const int RESOURCE_REMEMBERED = 0x00000003;

		const int RESOURCETYPE_ANY = 0x00000000;
		const int RESOURCETYPE_DISK = 0x00000001;
		const int RESOURCETYPE_PRINT = 0x00000002;

		const int RESOURCEDISPLAYTYPE_GENERIC = 0x00000000;
		const int RESOURCEDISPLAYTYPE_DOMAIN = 0x00000001;
		const int RESOURCEDISPLAYTYPE_SERVER = 0x00000002;
		const int RESOURCEDISPLAYTYPE_SHARE = 0x00000003;
		const int RESOURCEDISPLAYTYPE_FILE = 0x00000004;
		const int RESOURCEDISPLAYTYPE_GROUP = 0x00000005;

		const int RESOURCEUSAGE_CONNECTABLE = 0x00000001;
		const int RESOURCEUSAGE_CONTAINER = 0x00000002;


		const int CONNECT_INTERACTIVE = 0x00000008;
		const int CONNECT_PROMPT = 0x00000010;
		const int CONNECT_REDIRECT = 0x00000080;
		const int CONNECT_UPDATE_PROFILE = 0x00000001;
		const int CONNECT_COMMANDLINE = 0x00000800;
		const int CONNECT_CMD_SAVECRED = 0x00001000;

		const int CONNECT_LOCALDRIVE = 0x00000100;
		#endregion

		#region Errors
		const int NO_ERROR = 0;

		const int ERROR_ACCESS_DENIED = 5;
		const int ERROR_ALREADY_ASSIGNED = 85;
		const int ERROR_BAD_DEVICE = 1200;
		const int ERROR_BAD_NET_NAME = 67;
		const int ERROR_BAD_PROVIDER = 1204;
		const int ERROR_CANCELLED = 1223;
		const int ERROR_EXTENDED_ERROR = 1208;
		const int ERROR_INVALID_ADDRESS = 487;
		const int ERROR_INVALID_PARAMETER = 87;
		const int ERROR_INVALID_PASSWORD = 1216;
		const int ERROR_MORE_DATA = 234;
		const int ERROR_NO_MORE_ITEMS = 259;
		const int ERROR_NO_NET_OR_BAD_PATH = 1203;
		const int ERROR_NO_NETWORK = 1222;

		const int ERROR_BAD_PROFILE = 1206;
		const int ERROR_CANNOT_OPEN_PROFILE = 1205;
		const int ERROR_DEVICE_IN_USE = 2404;
		const int ERROR_NOT_CONNECTED = 2250;
		const int ERROR_OPEN_FILES  = 2401;

		private struct ErrorClass 
		{
			public int num;
			public string message;
			public ErrorClass(int num, string message) 
			{
				this.num = num;
				this.message = message;
			}
		}
		
		private static ErrorClass[] ERROR_LIST = new ErrorClass[] {
			new ErrorClass(ERROR_ACCESS_DENIED, "Error: Access Denied"), 
			new ErrorClass(ERROR_ALREADY_ASSIGNED, "Error: Already Assigned"), 
			new ErrorClass(ERROR_BAD_DEVICE, "Error: Bad Device"), 
			new ErrorClass(ERROR_BAD_NET_NAME, "Error: Bad Net Name"), 
			new ErrorClass(ERROR_BAD_PROVIDER, "Error: Bad Provider"), 
			new ErrorClass(ERROR_CANCELLED, "Error: Cancelled"), 
			new ErrorClass(ERROR_EXTENDED_ERROR, "Error: Extended Error"), 
			new ErrorClass(ERROR_INVALID_ADDRESS, "Error: Invalid Address"), 
			new ErrorClass(ERROR_INVALID_PARAMETER, "Error: Invalid Parameter"), 
			new ErrorClass(ERROR_INVALID_PASSWORD, "Error: Invalid Password"), 
			new ErrorClass(ERROR_MORE_DATA, "Error: More Data"), 
			new ErrorClass(ERROR_NO_MORE_ITEMS, "Error: No More Items"), 
			new ErrorClass(ERROR_NO_NET_OR_BAD_PATH, "Error: No Net Or Bad Path"), 
			new ErrorClass(ERROR_NO_NETWORK, "Error: No Network"), 
			new ErrorClass(ERROR_BAD_PROFILE, "Error: Bad Profile"), 
			new ErrorClass(ERROR_CANNOT_OPEN_PROFILE, "Error: Cannot Open Profile"), 
			new ErrorClass(ERROR_DEVICE_IN_USE, "Error: Device In Use"), 
			new ErrorClass(ERROR_EXTENDED_ERROR, "Error: Extended Error"), 
			new ErrorClass(ERROR_NOT_CONNECTED, "Error: Not Connected"), 
			new ErrorClass(ERROR_OPEN_FILES, "Error: Open Files"), 
		};

		private static string getErrorForNumber(int errNum) 
		{
			foreach (ErrorClass er in ERROR_LIST) 
			{
				if (er.num == errNum) return er.message;
			}
			return "Error: Unknown, " + errNum;
		}
		#endregion

		[DllImport("Mpr.dll")] private static extern int WNetUseConnection(
			IntPtr hwndOwner,
			NETRESOURCE lpNetResource,
			string lpPassword,
			string lpUserID,
			int dwFlags,
			string lpAccessName,
			string lpBufferSize,
			string lpResult
		);

		[DllImport("Mpr.dll")] private static extern int WNetCancelConnection2(
			string lpName,
			int dwFlags,
			bool fForce
		);

		[StructLayout(LayoutKind.Sequential)] private class NETRESOURCE
		{ 
			public int dwScope = 0;
			public int dwType = 0;
			public int dwDisplayType = 0;
			public int dwUsage = 0;
			public string lpLocalName = "";
			public string lpRemoteName = "";
			public string lpComment = "";
			public string lpProvider = "";
		}

        public static void Main(string[] args)
        {
            try
            { 
                if(args[0] == "connect" && args.Length == 5)
                {
                    connectToRemote(args[1], args[2], args[3], args[4], false);
                }
                else if(args[0] == "disconnect" && args.Length == 2)
                {
                    System.Console.WriteLine("Disconnecting {0}", args[1]);
                    disconnectRemote(args[1]);
                }
                else{
                        System.Console.WriteLine("Usage: \n\n Connecting: \n\t mountshare.exe connect [local drive letter (F:)] [remote share] [username] [password] \n\n Disconnecting: \n\t mountshare.exe disconnect [local drive letter]");
                }
            }
            catch {
                System.Console.WriteLine("Usage: \n\n Connecting: \n\t mountshare.exe connect [local drive letter (F:)] [remote share] [username] [password] \n\n Disconnecting: \n\t mountshare.exe disconnect [local drive letter]");
            }
        }
		public static void connectToRemote(string localdrive, string remoteUNC, string username, string password, bool promptUser) 
		{
			NETRESOURCE nr = new NETRESOURCE();
			nr.dwType = RESOURCETYPE_DISK;
			nr.lpRemoteName = remoteUNC;
            nr.lpLocalName = localdrive;
			//			nr.lpLocalName = "F:";

			System.Console.WriteLine("Connecting to share: {0} as username {1} with password {2}", remoteUNC, username, password); 
			int ret = WNetUseConnection(IntPtr.Zero, nr, password, username, 0, null, null, null);

			if (ret == NO_ERROR)
            {
                System.Console.WriteLine("Successfully mapped ");
            }
            else{
                System.Console.WriteLine("Error mapping the share: " + getErrorForNumber(ret));
            }
		}

		public static void disconnectRemote(string remoteUNC) 
		{
			int ret = WNetCancelConnection2(remoteUNC, CONNECT_UPDATE_PROFILE, false);
			if (ret == NO_ERROR) 
            {
                System.Console.WriteLine("Successfully disconnected {0}", remoteUNC);
            }
			else {
                System.Console.WriteLine("Error disconnecting: ", getErrorForNumber(ret));
            }
		}
	}
}
