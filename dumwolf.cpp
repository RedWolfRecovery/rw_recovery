/*
	Copyright 2018 ATG Droid
	This file is part of RWRP/RedWolf Recovery Project.

	RWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	RWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with RWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

// dumwolf.cpp - Source to unpack & repack boot/recovery images

using namespace std;
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include "twrp-functions.hpp"
#include "dumwolf.hpp"
#include "data.hpp"
#include "partitions.hpp"
#include "twcommon.h"
#include "cutils/properties.h"
#include "gui/gui.hpp"
#include "variables.h"

static string tmp = "/tmp/dumwolf";
static string ramdisk = tmp + "/ramdisk";
static string split_img = tmp + "/split_img";
static string default_prop = ramdisk + "/default.prop";

void RWDumwolf::Set_New_Ramdisk_Property(string prop, bool enable) {
if (TWFunc::CheckWord(default_prop, prop)) {
if (enable) {
string expected_value = prop + "=0";
prop += "=1";
TWFunc::Replace_Word_In_File(default_prop, expected_value, prop);
} else {
string expected_value = prop + "=1";
prop += "=0";
TWFunc::Replace_Word_In_File(default_prop, expected_value, prop);
}
} else {
ofstream File(default_prop.c_str(), ios_base::app | ios_base::out);  
if (File.is_open()) {
if (enable)
prop += "=1";
else
prop += "=0";
File << prop << endl;
File.close();
}
}
}

string RWDumwolf::Load_File(string extension) {
string line, path = split_img + "/" + extension;
ifstream File;
File.open (path);
if(File.is_open()) {
getline(File,line);
File.close();
}
return line;
}
  
bool RWDumwolf::Unpack_Image(string mount_point) {
string null;
if (TWFunc::Path_Exists(tmp))
TWFunc::removeDir(tmp, false);
if (!TWFunc::Recursive_Mkdir(ramdisk))
return false;
mkdir(split_img.c_str(), 0644);
TWPartition* Partition = PartitionManager.Find_Partition_By_Path(mount_point);
if (Partition == NULL || Partition->Current_File_System != "emmc") {
LOGERR("RWDumwolf::Unpack_Image: Partition don't exist or isn't emmc");
return false;
}
Read_Write_Specific_Partition("/tmp/dumwolf/boot.img", mount_point, true);
string Command = "unpackbootimg -i " + tmp + "/boot.img" + " -o " + split_img;
if (TWFunc::Exec_Cmd(Command, null) != 0) {
TWFunc::removeDir(tmp, false);
return false;
}
string local, result, hexdump;
DIR* dir;
struct dirent* der;
dir = opendir(split_img.c_str());
if (dir == NULL)
{
LOGINFO("Unable to open '%s'\n", split_img.c_str());
return false;
}
while ((der = readdir(dir)) != NULL)
{
Command = der->d_name;
if (Command.find("-ramdisk.") != string::npos)
break; 
}
closedir (dir);
if (Command.empty())
return false;
hexdump = "hexdump -vn2 -e '2/1 \"%x\"' " + split_img + "/" + Command;
if (TWFunc::Exec_Cmd(hexdump, result) != 0) {
TWFunc::removeDir(tmp, false);
return false;
}
if (result == "425a")
local = "bzip2 -dc";
else if (result == "1f8b" || result == "1f9e")
local = "gzip -dc";
else if (result == "0221")
local = "lz4 -d";
else if (result == "5d00")
local = "lzma -dc";
else if (result == "894c")
local = "lzop -dc";
else if (result == "fd37")
local = "xz -dc";
else
return false;
result = "cd " + ramdisk + "; " + local + " < " + split_img + "/" + Command + " | cpio -i";
if (TWFunc::Exec_Cmd(result, null) != 0) {
TWFunc::removeDir(tmp, false);
return false;
}
return true;
}

bool RWDumwolf::Resize_By_Path(string path) {
string null, local;
if (TWFunc::Path_Exists(tmp))
TWFunc::removeDir(tmp, false);
if (!TWFunc::Recursive_Mkdir(split_img))
return false;
string Command = "unpackbootimg -i " + path + " -o " + split_img;
TWFunc::Exec_Cmd(Command, null);
DIR* dir;
struct dirent* der;
dir = opendir(split_img.c_str());
if (dir == NULL)
{
LOGINFO("Unable to open '%s'\n", split_img.c_str());
return false;
}
Command = "mkbootimg";
while ((der = readdir(dir)) != NULL)
{
local = der->d_name;
if (local.find("-zImage") != string::npos) {
Command += " --kernel " + split_img + "/" + local;
continue;
}
if (local.find("-ramdisk.") != string::npos) {
Command += " --ramdisk " + split_img + "/" + local;
continue;
}
if (local.find("-dtb") != string::npos) {
Command += " --dt " + split_img + "/" + local;
continue;
}
if (local == "boot.img-second") {
Command += " --second " + split_img + "/" + local;
continue;
}
if (local.find("-secondoff") != string::npos) {
Command += " --second_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-cmdline") != string::npos) {
Command += " --cmdline \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-board") != string::npos) {
Command += " --board \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-base") != string::npos) {
Command += " --base " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-pagesize") != string::npos) {
Command += " --pagesize " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-kerneloff") != string::npos) {
Command += " --kernel_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-ramdiskoff") != string::npos) {
Command += " --ramdisk_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-tagsoff") != string::npos) {
Command += " --tags_offset \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-hash") != string::npos) {
if (Load_File(local) == "unknown")
Command += " --hash sha1";
else
Command += " --hash " + Load_File(local);
continue;
}
if (local.find("-osversion") != string::npos) {
Command += " --os_version \"" + Load_File(local) + "\"";
continue;
}
if (local.find("-oslevel") != string::npos) {
Command += " --os_patch_level \"" + Load_File(local) + "\"";
continue;
}
}
closedir (dir);
Command += " --output " + path;
if (TWFunc::Exec_Cmd(Command, null) != 0) {
TWFunc::removeDir(tmp, false);
return false;
}
char brand[PROPERTY_VALUE_MAX];
property_get("ro.product.manufacturer", brand, "");
Command = brand;
if (!Command.empty()) {
for (size_t i = 0; i < Command.size(); i++)
Command[i] = tolower(Command[i]);
if (Command == "samsung") {
ofstream File(path.c_str(), ios::binary);
	if (File.is_open()) {
		File << "SEANDROIDENFORCE" << endl;
		File.close();
	}
 }
   }
TWFunc::removeDir(tmp, false);
return true;
}
  


bool RWDumwolf::Repack_Image(string mount_point) {
string null, local, result, hexdump, Command;
DIR* dir;
struct dirent* der;
dir = opendir(split_img.c_str());
if (dir == NULL)
{
LOGINFO("Unable to open '%s'\n", split_img.c_str());
return false;
}
while ((der = readdir(dir)) != NULL)
{
local = der->d_name;
if (local.find("-ramdisk.") != string::npos)
break; 
}
closedir (dir);
if (local.empty())
return false;
hexdump = "hexdump -vn2 -e '2/1 \"%x\"' " + split_img + "/" + local;
TWFunc::Exec_Cmd(hexdump, result);
if (result == "425a")
local = "bzip2 -9c";
else if (result == "1f8b" || result == "1f9e")
local = "gzip -9c";
else if (result == "0221")
local = "lz4 -9";
else if (result == "5d00")
local = "lzma -c";
else if (result == "894c")
local = "lzop -9c";
else if (result == "fd37")
local = "xz --check=crc32 --lzma2=dict=2MiB";
else
return false;
string repack = "cd " + ramdisk + "; find | cpio -o -H newc | " + local + " > " + tmp + "/ramdisk-new";
TWFunc::Exec_Cmd(repack, null);
dir = opendir(split_img.c_str());
if (dir == NULL)
{
LOGINFO("Unable to open '%s'\n", split_img.c_str());
return false;
}
Command = "mkbootimg";
while ((der = readdir(dir)) != NULL)
{
local = der->d_name;
if (local.find("-zImage") != string::npos) {
Command += " --kernel " + split_img + "/" + local;
continue;
}
if (local.find("-ramdisk.") != string::npos) {
Command += " --ramdisk " + tmp + "/ramdisk-new";
continue;
}
if (local.find("-dtb") != string::npos) {
Command += " --dt " + split_img + "/" + local;
continue;
}
if (local == "boot.img-second") {
Command += " --second " + split_img + "/" + local;
continue;
}
if (local.find("-secondoff") != string::npos) {
Command += " --second_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-cmdline") != string::npos) {
Command += " --cmdline \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-board") != string::npos) {
Command += " --board \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-base") != string::npos) {
Command += " --base " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-pagesize") != string::npos) {
Command += " --pagesize " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-kerneloff") != string::npos) {
Command += " --kernel_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-ramdiskoff") != string::npos) {
Command += " --ramdisk_offset " + RWDumwolf::Load_File(local);
continue;
}
if (local.find("-tagsoff") != string::npos) {
Command += " --tags_offset \"" + RWDumwolf::Load_File(local) + "\"";
continue;
}
if (local.find("-hash") != string::npos) {
if (Load_File(local) == "unknown")
Command += " --hash sha1";
else
Command += " --hash " + Load_File(local);
continue;
}
if (local.find("-osversion") != string::npos) {
Command += " --os_version \"" + Load_File(local) + "\"";
continue;
}
if (local.find("-oslevel") != string::npos) {
Command += " --os_patch_level \"" + Load_File(local) + "\"";
continue;
}
}
closedir (dir);
Command += " --output " + tmp + "/boot.img";
rename("/tmp/dumwolf/boot.img", "/tmp/dumwolf/boot.img.bak");
if (TWFunc::Exec_Cmd(Command, null) != 0) {
TWFunc::removeDir(tmp, false);
return false;
}
char brand[PROPERTY_VALUE_MAX];
property_get("ro.product.manufacturer", brand, "");
hexdump = brand;
if (!hexdump.empty()) {
for (size_t i = 0; i < hexdump.size(); i++)
hexdump[i] = tolower(hexdump[i]);
if (hexdump == "samsung") {
ofstream File("/tmp/dumwolf/boot.img", ios::binary);
	if (File.is_open()) {
		File << "SEANDROIDENFORCE" << endl;
		File.close();
	}
 }
   }
Read_Write_Specific_Partition("/tmp/dumwolf/boot.img", mount_point, false);
TWFunc::removeDir(tmp, false);
return true;
}


bool RWDumwolf::Patch_DM_Verity() {
bool status = false;
string firmware_key = ramdisk + "/sbin/firmware_key.cer";
string path, cmp, remove = "verify,;,verify;verify;support_scfs,;,support_scfs;support_scfs;";
DIR* d;
struct dirent* de;
d = opendir(ramdisk.c_str());
if (d == NULL)
{
LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
return false;
}
while ((de = readdir(d)) != NULL)
{
cmp = de->d_name;
   path = ramdisk + "/" + cmp;
  if (cmp.find("fstab.") != string::npos) {
  gui_msg(Msg("wolf_dumwolf_fstab=Detected fstab: '{1}'")(cmp));
  if (!status) {
 if (TWFunc::CheckWord(path, "verify") || TWFunc::CheckWord(path, "support_scfs")) 
 status = true;
 }
TWFunc::Replace_Word_In_File(path, remove);
  }
  if (cmp == "default.prop") {
  if (TWFunc::CheckWord(path, "ro.config.dmverity=")) {
  if (TWFunc::CheckWord(path, "ro.config.dmverity=true"))
  TWFunc::Replace_Word_In_File(path, "ro.config.dmverity=true;", "ro.config.dmverity=false");
  } else {
             ofstream File(path.c_str(), ios_base::app | ios_base::out);  
             if (File.is_open()) {
             File << "ro.config.dmverity=false" << endl;
             File.close();
             }			
			}
		}
	    if (cmp == "verity_key") {
		if (!status)
		status = true;
		unlink(path.c_str());
	}
} 
closedir (d);
    if (TWFunc::Path_Exists(firmware_key)) {
    if (!status)
    status = true;
    unlink(firmware_key.c_str());
    }
return status;
}            
		


bool RWDumwolf::Patch_Forced_Encryption() {
string path, cmp;
bool status = false;
int encryption;
DataManager::GetValue(RW_DISABLE_DM_VERITY, encryption);
DIR* d;
struct dirent* de;
d = opendir(ramdisk.c_str());
if (d == NULL)
{
LOGINFO("Unable to open '%s'\n", ramdisk.c_str());
return false;
}
while ((de = readdir(d)) != NULL)
{
   cmp = de->d_name;
   path = ramdisk + "/" + cmp;
   if (cmp.find("fstab.") != string::npos) {
   	if (encryption != 1)
       gui_msg(Msg("wolf_dumwolf_fstab=Detected fstab: '{1}'")(cmp));
   	if (!status) {
       if (TWFunc::CheckWord(path, "forceencrypt") || TWFunc::CheckWord(path, "forcefdeorfbe"))
       status = true;
       }
       TWFunc::Replace_Word_In_File(path, "forcefdeorfbe=;forceencrypt=;", "encryptable=");
       }   
      }
      closedir (d);
     return status;
    }
    
void RWDumwolf::Deactivation_Process(void) {
if (!Unpack_Image("/boot")) {
LOGINFO("Deactivation_Process: Unable to unpack image\n");
return;
}
gui_msg(Msg(msg::kProcess, "wolf_run_process=Starting '{1}' process")("Dumwolf"));
if (DataManager::GetIntValue(RW_DISABLE_DM_VERITY) == 1) {
if (Patch_DM_Verity())
gui_process("wolf_dumwolf_dm_verity=Successfully patched DM-Verity");
else
gui_msg("wolf_dumwolf_dm_verity_off=DM-Verity is not enabled");
}
if (DataManager::GetIntValue(RW_DISABLE_FORCED_ENCRYPTION) == 1) {
if (Patch_Forced_Encryption())
gui_process("wolf_dumwolf_encryption=Successfully patched forced encryption");
else
gui_msg("wolf_dumwolf_encryption_off=Forced Encryption is not enabled");
}
if (DataManager::GetIntValue(RW_ENABLE_DEBUGGING) == 1)
Set_New_Ramdisk_Property("ro.debuggable", true);
else if (DataManager::GetIntValue(RW_DISABLE_DEBUGGING) == 1)
Set_New_Ramdisk_Property("ro.debuggable", false);
if (DataManager::GetIntValue(RW_ENABLE_ADB_RO) == 1)
Set_New_Ramdisk_Property("ro.adb.secure", true);
else if (DataManager::GetIntValue(RW_DISABLE_ADB_RO) == 1)
Set_New_Ramdisk_Property("ro.adb.secure", false);
if (DataManager::GetIntValue(RW_ENABLE_SECURE_RO) == 1)
Set_New_Ramdisk_Property("ro.secure", true);
else if (DataManager::GetIntValue(RW_DISABLE_SECURE_RO) == 1)
Set_New_Ramdisk_Property("ro.secure", false);
if (DataManager::GetIntValue(RW_ENABLE_MOCK_LOCATION) == 1)
Set_New_Ramdisk_Property("ro.allow.mock.location", true);
else if (DataManager::GetIntValue(RW_DISABLE_MOCK_LOCATION) == 1)
Set_New_Ramdisk_Property("ro.allow.mock.location", false);
if (!Repack_Image("/boot")) {
gui_msg(Msg(msg::kProcess, "wolf_run_process_fail=Unable to finish '{1}' process")("Dumwolf"));
return;
}
gui_msg(Msg(msg::kProcess, "wolf_run_process_done=Finished '{1}' process")("Dumwolf"));
return;
}

void RWDumwolf::Read_Write_Specific_Partition(string path, string partition_name, bool backup) {
	TWPartition* Partition = PartitionManager.Find_Partition_By_Path(partition_name);
	if (Partition == NULL || Partition->Current_File_System != "emmc") {
	LOGERR("Read_Write_Specific_Partition: Unable to find %s\n", partition_name.c_str());
	return;
	}
	string Read_Write, oldfile, null;
	unsigned long long Remain, Remain_old;
	oldfile = path + ".bak";
	if (backup)
	Read_Write = "dump_image " + Partition->Actual_Block_Device + " " + path;
	else {
    Read_Write = "flash_image " + Partition->Actual_Block_Device + " " + path;
   if (TWFunc::Path_Exists(oldfile)) {
    Remain_old = TWFunc::Get_File_Size(oldfile);
    Remain = TWFunc::Get_File_Size(path);
    if (Remain_old < Remain) {
    return;
    }
    }
    TWFunc::Exec_Cmd(Read_Write, null);
	return;
	}
	if (TWFunc::Path_Exists(path))
	unlink(path.c_str());
	TWFunc::Exec_Cmd(Read_Write, null);
	return;
}


    


            	   	               	   	   	   	   	   	      	   	               	   	   	   	   	   	               	   	               	   	   	   	   	   	      	   	               	   	   	   	   	   	   