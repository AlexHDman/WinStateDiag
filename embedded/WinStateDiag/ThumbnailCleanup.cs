// Deliberately narrow cleaner: verified Windows thumbnail databases only.
// No recursive deletion, no process termination, no path-based delete after analysis.
using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public static class WinDiagThumbnailCleanup {
 [StructLayout(LayoutKind.Sequential)]struct Info {public uint Attributes,CreateLo,CreateHi,AccessLo,AccessHi,WriteLo,WriteHi,Volume,SizeHi,SizeLo,Links,IndexHi,IndexLo;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref int info,uint size);
 public sealed class Item {public string Path,Hash,Identity;public long Bytes;public bool Deleted;}
 static Info Get(SafeFileHandle h){Info i;if(!GetFileInformationByHandle(h,out i))throw new Win32Exception();return i;}
 static SafeFileHandle Open(string path,uint access,uint flags){var h=CreateFile(path,access,1,IntPtr.Zero,3,flags,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new Win32Exception();}return h;}
 static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","");}
 public sealed class HeldPath : IDisposable {
  internal List<SafeFileHandle> Handles=new List<SafeFileHandle>();
  public void Dispose(){for(int i=Handles.Count-1;i>=0;i--)Handles[i].Dispose();Handles.Clear();}
 }
 public static HeldPath HoldPackage(string path){
  path=System.IO.Path.GetFullPath(path);if(path.StartsWith(@"\\"))throw new IOException("Network MSI packages are not supported; select a local copy");
  var lease=new HeldPath();
  try {
   string current=System.IO.Path.GetPathRoot(path);var first=Open(current,0x80,0x02200000);lease.Handles.Add(first);if((Get(first).Attributes&0x400)!=0)throw new IOException("Reparse root");
   string directory=System.IO.Path.GetDirectoryName(path);
   foreach(string part in directory.Substring(current.Length).Split('\\')){if(part.Length==0)continue;current=System.IO.Path.Combine(current,part);var h=Open(current,0x80,0x02200000);lease.Handles.Add(h);if((Get(h).Attributes&0x400)!=0)throw new IOException("Reparse package ancestor");}
   var file=Open(path,0x80000000,0x00200000);lease.Handles.Add(file);var info=Get(file);if((info.Attributes&(0x400|0x10))!=0||info.Links!=1)throw new IOException("MSI reparse/hardlink rejected");
   return lease;
  }catch{lease.Dispose();throw;}
 }
 public static Item Inspect(string root,string path,string expectedHash,string expectedIdentity,bool delete){
  root=System.IO.Path.GetFullPath(root).TrimEnd('\\');path=System.IO.Path.GetFullPath(path);
  if(!string.Equals(System.IO.Path.GetDirectoryName(path),root,StringComparison.OrdinalIgnoreCase))throw new IOException("Outside selected cache root");
  string name=System.IO.Path.GetFileName(path);
  if(!name.StartsWith("thumbcache_",StringComparison.OrdinalIgnoreCase)||!name.EndsWith(".db",StringComparison.OrdinalIgnoreCase))throw new IOException("Not a thumbnail cache database");
  if(root.StartsWith(@"\\")||root.Length<3)throw new IOException("Unsupported root");
  var parents=new List<SafeFileHandle>();
  try{
   // Deny write/delete sharing while every ancestor is checked and held.
   string current=System.IO.Path.GetPathRoot(root);var components=root.Substring(current.Length).Split('\\');
   var first=Open(current,0x80,0x02200000);parents.Add(first);if((Get(first).Attributes&0x400)!=0)throw new IOException("Reparse root");
   foreach(string part in components){if(part.Length==0)continue;current=System.IO.Path.Combine(current,part);var h=Open(current,0x80,0x02200000);parents.Add(h);if((Get(h).Attributes&0x400)!=0)throw new IOException("Reparse ancestor");}
   using(var h=Open(path,delete?0x80010000u:0x80000000u,0x00200000)){
    Info i=Get(h);if((i.Attributes&(0x400|0x10))!=0||i.Links!=1)throw new IOException("Reparse/directory/hardlink rejected");
    long size=((long)i.SizeHi<<32)|i.SizeLo;if(size<4||size>64L*1024*1024)throw new IOException("Cache size limit");
    using(var stream=new FileStream(h,FileAccess.Read)){
     byte[] magic=new byte[4];if(stream.Read(magic,0,4)!=4||System.Text.Encoding.ASCII.GetString(magic)!="CMMM")throw new IOException("Unknown cache format");
     stream.Position=0;string hash;using(var sha=SHA256.Create())hash=Hex(sha.ComputeHash(stream));
     string identity=i.Volume.ToString("X8")+":"+i.IndexHi.ToString("X8")+i.IndexLo.ToString("X8");
     var result=new Item{Path=path,Hash=hash,Identity=identity,Bytes=size,Deleted=false};
     if(delete){if(hash!=expectedHash||identity!=expectedIdentity)throw new IOException("Stale selected file");int disposition=1;if(!SetFileInformationByHandle(h,4,ref disposition,4))throw new Win32Exception();result.Deleted=true;}
     return result;
    }
   }
  }finally{for(int n=parents.Count-1;n>=0;n--)parents[n].Dispose();}
 }
}
