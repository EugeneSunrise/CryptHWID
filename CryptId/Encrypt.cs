using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using static CryptID.RegEdit;

namespace CryptID
{
    #region RegEdit
    public class RegEdit
    {
        public static void Write(string Folder, string Param, string Value)
        {
            RegistryKey registryKey = Registry.CurrentUser.CreateSubKey("Software\\Mix\\" + Folder);
            registryKey.SetValue(Param, Value);
            registryKey.Dispose();
        }

        public static string Read(string Folder, string Param)
        {
            RegistryKey registryKey = (Registry.CurrentUser.OpenSubKey("Software\\Mix\\" + Folder) != null) ? Registry.CurrentUser.OpenSubKey("Software\\Mix\\" + Folder) : Registry.CurrentUser;
            string text = (string)registryKey.GetValue(Param);
            return (text == null || !(text != "")) ? PackageLow.ToPackageLow("Not", 7) : text;
        }

        public static void DeleteValue(string Folder, string Param)
        {
            RegistryKey registryKey = (Registry.CurrentUser.OpenSubKey(Folder, true) != null) ? Registry.CurrentUser.OpenSubKey(Folder, true) : Registry.CurrentUser.OpenSubKey(Folder, true);
            registryKey.DeleteValue(Param, true);
            registryKey.Dispose();
        }

        public static void DeleteKey(string Folder)
        {
            Registry.CurrentUser.DeleteSubKey(Folder, true);
        }

        public class Security
        {
            public static string Read(string Folder, string Param)
            {
                return CryptUN.ToString(RegEdit.Read(Folder, CryptUN.ToAUN(Param)));
            }

            public static void Write(string Folder, string Param, string Value)
            {
                RegEdit.Write(Folder, CryptUN.ToAUN(Param), CryptUN.ToAUN(Value));
            }

        }
    }
    #endregion
    #region Base64
    public class Base64
    {
        public static string ToBase64(string String)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(String));
        }

        public static string ToString(string Base64)
        {
            string result;
            try
            {
                result = Encoding.UTF8.GetString(Convert.FromBase64String(Base64));
            }
            catch
            {
                result = Base64;
            }
            return result;
        }
    }
    #endregion
    #region CryptBYB6
    public class CryptBYB6
    {
        public static string ToBYB6(string String)
        {
            string result;
            try
            {
                for (int i = 0; i < 5; i++)
                {
                    String = Base64.ToBase64(String);
                }
                result = String;
            }
            catch
            {
                result = "Not";
            }
            return result;
        }

        public static string ToString(string String)
        {
            string result;
            try
            {
                for (int i = 0; i < 5; i++)
                {
                    String = Base64.ToString(String);
                }
                result = String;
            }
            catch
            {
                result = "Not";
            }
            return result;
        }
    }
    #endregion
    #region CryptUN
    public class CryptUN
    {
        public static string ToAUN(string String)
        {
            string text = string.Empty;
            foreach (char c in CryptBYB6.ToBYB6(String))
            {
                try
                {
                    text = text + "$" + (Convert.ToInt32(c.ToString()) * 5 - 3).ToString();
                }
                catch
                {
                    text = text + "$" + c.ToString();
                }
            }
            return text.Remove(0, 1).Replace('/', '^').Replace('+', ',').Replace('=', '*');
        }
        public static string ToString(string String)
        {
            string text = string.Empty;
            string[] array = String.Split(new char[]
            {
                 '$'
            });
            foreach (string text2 in array)
            {
                try
                {
                    text += ((Convert.ToInt32(text2.ToString()) + 3) / 5).ToString();
                }
                catch
                {
                    text += text2;
                }
            }
            return CryptBYB6.ToString(text.Replace('*', '=').Replace(',', '+').Replace('^', '/'));
        }
    }
    #endregion
    #region License
    public class Licence
    {
        public static string GetUHId()
        {
            StringBuilder stringBuilder = new StringBuilder();
            ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_Processor");
            foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
            {
                ManagementObject managementObject = (ManagementObject)managementBaseObject;
                stringBuilder.Append(managementObject["NumberOfCores"]);
                stringBuilder.Append(managementObject["ProcessorId"]);
                stringBuilder.Append(managementObject["Name"]);
                stringBuilder.Append(managementObject["SocketDesignation"]);
                Console.WriteLine(managementObject["ProcessorId"]);
                Console.WriteLine(managementObject["Name"]);
                Console.WriteLine(managementObject["SocketDesignation"]);
            }
            managementObjectSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_BIOS");
            foreach (ManagementBaseObject managementBaseObject2 in managementObjectSearcher.Get())
            {
                ManagementObject managementObject2 = (ManagementObject)managementBaseObject2;
                stringBuilder.Append(managementObject2["Manufacturer"]);
                stringBuilder.Append(managementObject2["Name"]);
                stringBuilder.Append(managementObject2["Version"]);
                Console.WriteLine(managementObject2["Manufacturer"]);
                Console.WriteLine(managementObject2["Name"]);
                Console.WriteLine(managementObject2["Version"]);
            }
            managementObjectSearcher = new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_BaseBoard");
            foreach (ManagementBaseObject managementBaseObject3 in managementObjectSearcher.Get())
            {
                ManagementObject managementObject3 = (ManagementObject)managementBaseObject3;
                stringBuilder.Append(managementObject3["Product"]);
                Console.WriteLine(managementObject3["Product"]);
            }
            byte[] bytes = Encoding.ASCII.GetBytes(stringBuilder.ToString());
            SHA256Managed sha256Managed = new SHA256Managed();
            byte[] value = sha256Managed.ComputeHash(bytes);
            return BitConverter.ToString(value).Replace("-", "");
        }
        public static bool CheckLic(string AppName)
        {
            string uhid = GetUHId();
            Console.WriteLine("ID: " + uhid);
            Console.WriteLine("License ID: " + CryptUN.ToString(Security.Read(AppName, "License")));
            return CryptUN.ToString(Security.Read(AppName, "License")) == uhid;
        }
        public static void ActivatedLicense(string AppName, string Key)
        {
            if (!string.IsNullOrWhiteSpace(Key))
            {
                try
                {
                    if (GetUHId() == CryptUN.ToString(Key))
                    {
                        Security.Write(AppName, "License", Key);
                    }
                    else
                    {
                        MessageBox.Show("Недействительный ключ!");
                        Environment.Exit(0);
                    }
                    return;
                }
                catch { }
            }
            MessageBox.Show("Ключ не введен!");
            Environment.Exit(0);
        }
    }
    #endregion
    #region PackageLow
    public class PackageLow
    {
        public static string ToPackageLow(string String, int Count)
        {
            string text = String;
            for (int i = 0; i < Count; i++)
            {
                text = new PackageLow.ClassWork().method_0(text, Count);
            }
            return text;
        }

        public static string StringEquals(string String, int Count)
        {
            string text = String;
            for (int i = 0; i < Count; i++)
            {
                text = new PackageLow.ClassWork().method_0(text, -Count);
            }
            return text;
        }


        internal class ClassToPackageLow
        {
            private string string_0;
            public string method_0(string string_1, int int_0)
            {
                int num = this.string_0.IndexOf(string_1);
                string result;
                if (num == -1)
                {
                    result = "";
                }
                else
                {
                    num = (num + int_0) % this.string_0.Length;
                    if (num < 0)
                    {
                        num += this.string_0.Length;
                    }
                    result = this.string_0.Substring(num, 1);
                }
                return result;
            }
            public ClassToPackageLow()
            {
                string_0 = "";
            }
        }

        internal class ClassWork : List<PackageLow.ClassToPackageLow>
        {
            public string method_0(string string_0, int int_0)
            {
                string text = string.Empty;
                string text2 = string.Empty;
                for (int i = 0; i < string_0.Length; i++)
                {
                    foreach (PackageLow.ClassToPackageLow @class in this)
                    {
                        text2 = @class.method_0(string_0.Substring(i, 1), int_0);
                        if (text2 != "")
                        {
                            text += text2;
                            break;
                        }
                    }
                    if (text2 == "")
                    {
                        text += string_0.Substring(i, 1);
                    }
                }
                return text;
            }
        }
    }
    #endregion
}



