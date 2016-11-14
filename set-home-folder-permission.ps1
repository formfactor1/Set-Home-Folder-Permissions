<#
Powershell script that can be used to set permission for home folders and folders that are created via group policy.
Simply change line 8 to match your folder structure and modify line 16 to match your domain
#>
#Powershell script to set home folder permissions for all folders in the specified path

#Get username
$UserName=GET-CHILDITEM C:\test | Select-Object Name

#get all folders in path set below and place in variable, enter the path to the home folder below
$ScanFolders=GET-CHILDITEM -Directory C:\test -Recurse -Filter scan | Select-Object FullName
 
ForEach($loginname in $UserName)
    {
        #set domain below
        $global:domianusername=’domain\’+$loginname.Name
    }

#Loop to modify each folder in the path set above
Foreach ($Folder in $ScanFolders)
{
   
#retrieve current folder ACL's
 $Access=GET-ACL $Folder.FullName
 

#Set Rights that will be changed in following variables
#for rights available see http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx
$FileSystemRights=[System.Security.AccessControl.FileSystemRights]"FullControl"
$AccessControlType=[System.Security.AccessControl.AccessControlType]"Allow"
$InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$PropagationFlags=[System.Security.AccessControl.PropagationFlags]"InheritOnly"
$IdentityReference=$global:domianusername

#print what folder is being modified currently
Write-host $Folder.FullName

#Build command to modify folder ACL's and place in variable
$FileSystemAccessRule=New-Object System.Security.AccessControl.FileSystemAccessRule ($IdentityReference, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
 
$Access.AddAccessRule($FileSystemAccessRule)
 
#Set ACL's on Folder being modified
 SET-ACL -Path $Folder.FullName -AclObject $Access
  
}

#NOTES

#use get-executionpolicy to view what the script execution polily is
#use Set-executionpolicy to set the policy options are Unrestricted | RemoteSigned | AllSigned | Restricted

#The possible values for Rights are 
# ListDirectory, ReadData, WriteData 
# CreateFiles, CreateDirectories, AppendData 
# ReadExtendedAttributes, WriteExtendedAttributes, Traverse
# ExecuteFile, DeleteSubdirectoriesAndFiles, ReadAttributes 
# WriteAttributes, Write, Delete 
# ReadPermissions, Read, ReadAndExecute 
# Modify, ChangePermissions, TakeOwnership
# Synchronize, FullControl