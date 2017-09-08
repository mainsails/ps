using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PSSM
{
    public class Msi
    {
        enum LoadLibraryFlags : int
        {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL  = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE  = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE  = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE  = 0x00000020,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, LoadLibraryFlags dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
        static extern int LoadString(IntPtr hInstance, int uID, StringBuilder lpBuffer, int nBufferMax);

        public static string GetMessageFromMsiExitCode(int errCode)
        {
            IntPtr hModuleInstance = LoadLibraryEx("msimsg.dll", IntPtr.Zero, LoadLibraryFlags.LOAD_LIBRARY_AS_DATAFILE);

              StringBuilder sb = new StringBuilder(255);
              LoadString(hModuleInstance, errCode, sb, sb.Capacity + 1);

              return sb.ToString();
        }
    }
}