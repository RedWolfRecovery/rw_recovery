 /*
	Copyright 2012 to 2017 bigbiff/Dees_Troy TeamWin
	This file is part of TWRP/TeamWin Recovery Project.
	TWRP is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	TWRP is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include <string.h>
#include <stdio.h>

#include "twcommon.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"

#ifdef USE_MINZIP
#include "minzip/SysUtil.h"
#else
#include "otautil/SysUtil.h"
#include <ziparchive/zip_archive.h>
#endif
#include "zipwrap.hpp"
#ifdef USE_OLD_VERIFIER
#include "verifier24/verifier.h"
#else
#include "verifier.h"
#endif
#include "variables.h"
#include "cutils/properties.h"
#include "data.hpp"
#include "partitions.hpp"
#include "twrpDigestDriver.hpp"
#include "twrpDigest/twrpDigest.hpp"
#include "twrpDigest/twrpMD5.hpp"
#include "twrp-functions.hpp"
#include "gui/gui.hpp"
#include "gui/pages.hpp"
#include "gui/blanktimer.hpp"
#include "legacy_property_service.h"
#include "twinstall.h"
#include "dumwolf.hpp"
#include "installcommand.h"
extern "C" {
	#include "gui/gui.h"
}

#define AB_OTA "payload_properties.txt"
#define OTA_CORRUPT "INSTALL_CORRUPT"
#define OTA_ERROR "INSTALL_ERROR"
#define OTA_VERIFY_FAIL "INSTALL_VERIFY_FAILURE"
#define OTA_SUCCESS "INSTALL_SUCCESS"

#define WOLF_TMP_PATH "/wolftmpfile"

static const char* properties_path = "/dev/__properties__";
static const char* properties_path_renamed = "/dev/__properties_kk__";
static bool legacy_props_env_initd = false;
static bool legacy_props_path_modified = false;
static bool zip_is_for_specific_build = false;
static bool zip_is_rom_package = false;
static bool zip_survival_failed = false;
static bool zip_is_survival_trigger = false;

enum zip_type {
	UNKNOWN_ZIP_TYPE = 0,
	UPDATE_BINARY_ZIP_TYPE,
	AB_OTA_ZIP_TYPE
};

static std::string get_survival_path()
{
        std::string ota_location_folder, ota_location_backup;
        DataManager::GetValue(RW_SURVIVAL_FOLDER_VAR, ota_location_folder);
		DataManager::GetValue(RW_SURVIVAL_BACKUP_NAME, ota_location_backup);
		ota_location_folder += "/" + ota_location_backup;
        return ota_location_folder;
}

static bool storage_is_encrypted()
{
return (DataManager::GetIntValue(TW_IS_ENCRYPTED) || !DataManager::GetIntValue(TW_IS_DECRYPTED)) ? false : true;
}	

static bool ors_is_active()
{    
return (DataManager::GetStrValue("tw_action") != "openrecoveryscript") ? false : true;
}

// to support pre-KitKat update-binaries that expect properties in the legacy format
static int switch_to_legacy_properties()
{
	if (!legacy_props_env_initd) {
		if (legacy_properties_init() != 0)
			return -1;

		char tmp[32];
		int propfd, propsz;
		legacy_get_property_workspace(&propfd, &propsz);
		sprintf(tmp, "%d,%d", dup(propfd), propsz);
		setenv("ANDROID_PROPERTY_WORKSPACE", tmp, 1);
		legacy_props_env_initd = true;
	}

	if (TWFunc::Path_Exists(properties_path)) {
		// hide real properties so that the updater uses the envvar to find the legacy format properties
		if (rename(properties_path, properties_path_renamed) != 0) {
			LOGERR("Renaming %s failed: %s\n", properties_path, strerror(errno));
			return -1;
		} else {
			legacy_props_path_modified = true;
		}
	}

	return 0;
}

static int switch_to_new_properties()
{
	if (TWFunc::Path_Exists(properties_path_renamed)) {
		if (rename(properties_path_renamed, properties_path) != 0) {
			LOGERR("Renaming %s failed: %s\n", properties_path_renamed, strerror(errno));
			return -1;
		} else {
			legacy_props_path_modified = false;
		}
	}

	return 0;
}

static void set_miui_install_status(std::string install_status, bool verify)
{
if (DataManager::GetStrValue("tw_action") == "openrecoveryscript") {
std::string last_status = "/cache/recovery/last_status";
if (!PartitionManager.Mount_By_Path("/cache", true))
return;
if (!verify) {
if (zip_is_survival_trigger || zip_is_for_specific_build) {
    if (TWFunc::Path_Exists(last_status)) 
    unlink(last_status.c_str());
    
     ofstream status;
     status.open (last_status.c_str());
     status << install_status;
     status.close();
     chmod(last_status.c_str(), 0755);  
    }
   } else {
    if (TWFunc::Path_Exists(last_status)) 
    unlink(last_status.c_str());
    
     ofstream status;
     status.open (last_status.c_str());
     status << install_status;
     status.close();
     chmod(last_status.c_str(), 0755);  
     }
	 }
}

static std::string get_metadata_property(std::vector<string> metadata, std::string Property) {
 int i, l = metadata.size();
 size_t start = 0, end;
 std::string local;
 for (i = 0;i < l;i++) {
  end = metadata.at(i).find("=", start);
  local = metadata.at(i).substr(start, end);
  if (local == Property) {
    local = metadata.at(i).substr(end + 1, metadata.at(i).size());
    return local;
  }
 }
 return local;
}
	

static bool verify_incremental_package(string fingerprint, string metadatafp, string metadatadevice)
{
	if (metadatafp.size() > RW_MIN_EXPECTED_FP_SIZE && fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE && metadatafp != fingerprint)
	return false;
	if (metadatadevice.size() >= 4 && fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE && fingerprint.find(metadatadevice) == string::npos)
	return false;
	return (metadatadevice.size() >= 4 && metadatafp.size() > RW_MIN_EXPECTED_FP_SIZE && metadatafp.find(metadatadevice) == string::npos) ? false : true;
}

static int Prepare_Update_Binary(const char *path, ZipWrap *Zip, int* wipe_cache) {
std::string fingerprint_property = "ro.build.fingerprint";
std::string metadata_fingerprint;
std::vector<string> metadata;

	if (!Zip->ExtractEntry(ASSUMED_UPDATE_BINARY_NAME, TMP_UPDATER_BINARY_PATH, 0755)) {
		Zip->Close();
		LOGERR("Could not extract '%s'\n", ASSUMED_UPDATE_BINARY_NAME);
		return INSTALL_ERROR;
	}		
         if (DataManager::GetIntValue(RW_INCREMENTAL_PACKAGE) != 0) {
	       gui_msg("wolf_install_detecting=Detecting Current Package");
	       if (Zip->EntryExists(UPDATER_SCRIPT)) {
		   if (Zip->ExtractEntry(UPDATER_SCRIPT, WOLF_TMP_PATH, 0644)) {
		    if (TWFunc::CheckWord(WOLF_TMP_PATH, "block_image_update"))
		    zip_is_rom_package = true;
		    unlink(WOLF_TMP_PATH);
		    }
		  }
          if (!Zip->EntryExists(DataManager::GetStrValue(RW_MAIN_SURVIVAL_TRIGGER))) {
           gui_msg("wolf_install_standard_detected=- Detected standard Package");       
            } else {
	       zip_is_survival_trigger = true;
	       gui_msg("wolf_install_miui_detected=- Detected Survival Trigger Package");
        }		    
	    gui_msg("wolf_incremental_ota_status_enabled=Support MIUI Incremental package status: Enabled");
	    if (zip_is_survival_trigger) {
	    if (Zip->EntryExists(METADATA)) {
		if (Zip->ExtractEntry(METADATA, WOLF_TMP_PATH, 0644)) {
        if (TWFunc::read_file(WOLF_TMP_PATH, metadata) == 0) {
		metadata_fingerprint = get_metadata_property(metadata, "pre-build");
		std::string metadata_device = get_metadata_property(metadata, "pre-device");
        string fingerprint = TWFunc::System_Property_Get(fingerprint_property);
        unlink(WOLF_TMP_PATH);
		if (metadata_fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE) {
		gui_msg(Msg("wolf_incremental_package_detected=Detected Incremental package '{1}'")(path));
		zip_is_for_specific_build = true;
		if (fingerprint.size() > RW_MIN_EXPECTED_FP_SIZE && DataManager::GetIntValue("wolf_verify_incremental_ota_signature") != 0) {
		gui_msg("wolf_incremental_ota_compatibility_chk=Verifying Incremental Package Signature...");
		if (verify_incremental_package(fingerprint, metadata_fingerprint, metadata_device)) {
		gui_msg("wolf_incremental_ota_compatibility_true=Incremental package is compatible.");
		property_set(fingerprint_property.c_str(), metadata_fingerprint.c_str());
	    } else {
		set_miui_install_status(OTA_VERIFY_FAIL, false);
		gui_err("wolf_incremental_ota_compatibility_false=Incremental package isn't compatible with this ROM!");
		return INSTALL_ERROR;
		}
		} else {
		property_set(fingerprint_property.c_str(), metadata_fingerprint.c_str());
		}
        if (zip_is_for_specific_build) {  	
        if (!ors_is_active() && zip_is_rom_package)
        gui_warn("wolf_zip_have_to_be_decrypted=Warning: Some OEMs specific packages have to be first decrypted before the installation!");
        }   
          TWPartition* Boot = PartitionManager.Find_Partition_By_Path("/boot");
          if (Boot == NULL) {
       	LOGERR("Unable to find boot partition!");
           return INSTALL_ERROR;
           }
        std::string survival_folder = get_survival_path();
        std::string Boot_File = survival_folder + "/boot." + Boot->Current_File_System + ".win";
        if (storage_is_encrypted()) {
        set_miui_install_status(OTA_CORRUPT, false);
        return INSTALL_ERROR;
        }	
        if (!TWFunc::Path_Exists(Boot_File)) {
        set_miui_install_status(OTA_CORRUPT, false);
        gui_err("wolf_survival_does_not_exist=OTA Survival does not exist! Please flash a full ROM first!");
        return INSTALL_ERROR;
        }
		gui_msg(Msg(msg::kProcess, "wolf_run_process=Starting '{1}' process")("OTA_RES"));
		DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 1);
		PartitionManager.Set_Restore_Files(survival_folder);		
		if (PartitionManager.Run_Custom_Restore(survival_folder)) {
		gui_msg(Msg(msg::kProcess, "wolf_run_process_done=Finished '{1}' process")("OTA_RES"));
		DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 0);
		} else {
		DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 0);
        set_miui_install_status(OTA_ERROR, false);
		gui_msg(Msg(msg::kProcess, "wolf_run_process_fail=Unable to finish '{1}' process")("OTA_RES"));
	    return INSTALL_ERROR;
	     }
	  }
  }
  }
 }
 }
  } else {
	gui_msg("wolf_incremental_ota_status_disabled=Support MIUI Incremental package status: Disabled");
  }
  
   if (blankTimer.isScreenOff()) {
   if (Zip->EntryExists(AROMA_CONFIG)) {
		blankTimer.toggleBlank();
		gui_changeOverlay("");
		}
      }
  
		// If exists, extract file_contexts from the zip file
	if (!Zip->EntryExists("file_contexts")) {
		Zip->Close();
		LOGINFO("Zip does not contain SELinux file_contexts file in its root.\n");
	} else {
		const string output_filename = "/file_contexts";
		LOGINFO("Zip contains SELinux file_contexts file in its root. Extracting to %s\n", output_filename.c_str());
		if (!Zip->ExtractEntry("file_contexts", output_filename, 0644)) {
			Zip->Close();
			set_miui_install_status(OTA_CORRUPT, false);
			LOGERR("Could not extract '%s'\n", output_filename.c_str());
			return INSTALL_ERROR;
		}
	}
	Zip->Close();
	return INSTALL_SUCCESS;
}

static bool update_binary_has_legacy_properties(const char *binary) {
	const char str_to_match[] = "ANDROID_PROPERTY_WORKSPACE";
	int len_to_match = sizeof(str_to_match) - 1;
	bool found = false;

	int fd = open(binary, O_RDONLY);
	if (fd < 0) {
		LOGINFO("has_legacy_properties: Could not open %s: %s!\n", binary, strerror(errno));
		return false;
	}

	struct stat finfo;
	if (fstat(fd, &finfo) < 0) {
		LOGINFO("has_legacy_properties: Could not fstat %d: %s!\n", fd, strerror(errno));
		close(fd);
		return false;
	}

	void *data = mmap(NULL, finfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		LOGINFO("has_legacy_properties: mmap (size=%lld) failed: %s!\n", finfo.st_size, strerror(errno));
	} else {
		if (memmem(data, finfo.st_size, str_to_match, len_to_match)) {
			LOGINFO("has_legacy_properties: Found legacy property match!\n");
			found = true;
		}
		munmap(data, finfo.st_size);
	}
	close(fd);

	return found;
}

static int Run_Update_Binary(const char *path, ZipWrap *Zip, int* wipe_cache, zip_type ztype) {
	int ret_val, pipe_fd[2], status, zip_verify;
	char buffer[1024];
	FILE* child_data;

#ifndef TW_NO_LEGACY_PROPS
	if (!update_binary_has_legacy_properties(TMP_UPDATER_BINARY_PATH)) {
		LOGINFO("Legacy property environment not used in updater.\n");
	} else if (switch_to_legacy_properties() != 0) { /* Set legacy properties */
		LOGERR("Legacy property environment did not initialize successfully. Properties may not be detected.\n");
	} else {
		LOGINFO("Legacy property environment initialized.\n");
	}
#endif

	pipe(pipe_fd);

	std::vector<std::string> args;
    if (ztype == UPDATE_BINARY_ZIP_TYPE) {
		ret_val = update_binary_command(path, 0, pipe_fd[1], &args);
    } else if (ztype == AB_OTA_ZIP_TYPE) {
		ret_val = abupdate_binary_command(path, Zip, 0, pipe_fd[1], &args);
	} else {
		LOGERR("Unknown zip type %i\n", ztype);
		ret_val = INSTALL_CORRUPT;
	}
    if (ret_val) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return ret_val;
    }

	// Convert the vector to a NULL-terminated char* array suitable for execv.
	const char* chr_args[args.size() + 1];
	chr_args[args.size()] = NULL;
	for (size_t i = 0; i < args.size(); i++)
		chr_args[i] = args[i].c_str();

	pid_t pid = fork();
	if (pid == 0) {
		close(pipe_fd[0]);
		execve(chr_args[0], const_cast<char**>(chr_args), environ);
		printf("E:Can't execute '%s': %s\n", chr_args[0], strerror(errno));
		_exit(-1);
	}
	close(pipe_fd[1]);

	*wipe_cache = 0;

	DataManager::GetValue(TW_SIGNED_ZIP_VERIFY_VAR, zip_verify);
	child_data = fdopen(pipe_fd[0], "r");
	while (fgets(buffer, sizeof(buffer), child_data) != NULL) {
		char* command = strtok(buffer, " \n");
		if (command == NULL) {
			continue;
		} else if (strcmp(command, "progress") == 0) {
			char* fraction_char = strtok(NULL, " \n");
			char* seconds_char = strtok(NULL, " \n");

			float fraction_float = strtof(fraction_char, NULL);
			int seconds_float = strtol(seconds_char, NULL, 10);

			if (zip_verify)
				DataManager::ShowProgress(fraction_float * (1 - VERIFICATION_PROGRESS_FRAC), seconds_float);
			else
				DataManager::ShowProgress(fraction_float, seconds_float);
		} else if (strcmp(command, "set_progress") == 0) {
			char* fraction_char = strtok(NULL, " \n");
			float fraction_float = strtof(fraction_char, NULL);
			DataManager::SetProgress(fraction_float);
		} else if (strcmp(command, "ui_print") == 0) {
			char* display_value = strtok(NULL, "\n");
			if (display_value) {
				gui_print("%s", display_value);
       } else {
				gui_print("\n");
			}
		} else if (strcmp(command, "wipe_cache") == 0) {
			*wipe_cache = 1;
		} else if (strcmp(command, "clear_display") == 0) {
			// Do nothing, not supported by TWRP
		} else if (strcmp(command, "log") == 0) {
			printf("%s\n", strtok(NULL, "\n"));
		} else {
			LOGERR("unknown command [%s]\n", command);
		}
	}
	fclose(child_data);

	int waitrc = TWFunc::Wait_For_Child(pid, &status, "Updater");

#ifndef TW_NO_LEGACY_PROPS
	/* Unset legacy properties */
	if (legacy_props_path_modified) {
		if (switch_to_new_properties() != 0) {
			LOGERR("Legacy property environment did not disable successfully. Legacy properties may still be in use.\n");
		} else {
			LOGINFO("Legacy property environment disabled.\n");
		}
	}
#endif

	if (waitrc != 0) {
		set_miui_install_status(OTA_CORRUPT, false);
		return INSTALL_ERROR;
        }
        
	return INSTALL_SUCCESS;
}

int TWinstall_zip(const char* path, int* wipe_cache) {
	int ret_val, zip_verify = 1;

	if (strcmp(path, "error") == 0) {
		LOGERR("Failed to get adb sideload file: '%s'\n", path);
		return INSTALL_CORRUPT;
	}
	
	gui_msg(Msg("installing_zip=Installing zip file '{1}'")(path));
	if (strlen(path) < 9 || strncmp(path, "/sideload", 9) != 0) {
		string digest_str;
		string Full_Filename = path;
		string digest_file = path;
		digest_file += ".md5";

		gui_msg("check_for_digest=Checking for Digest file...");
		if (!TWFunc::Path_Exists(digest_file)) {
			gui_msg("no_digest=Skipping Digest check: no Digest file found");
		}
		else {
			if (TWFunc::read_file(digest_file, digest_str) != 0) {
				LOGERR("Skipping MD5 check: MD5 file unreadable\n");
			}
			else {
				twrpDigest *digest = new twrpMD5();
				if (!twrpDigestDriver::stream_file_to_digest(Full_Filename, digest)) {
					delete digest;
					return INSTALL_CORRUPT;
				}
				string digest_check = digest->return_digest_string();
				if (digest_str == digest_check) {
					gui_msg(Msg("digest_matched=Digest matched for '{1}'.")(path));
				}
				else {
					LOGERR("Aborting zip install: Digest verification failed\n");
					set_miui_install_status(OTA_CORRUPT, true);
					delete digest;
					return INSTALL_CORRUPT;
				}
				delete digest;
			}
		}
	}

#ifndef TW_OEM_BUILD
	DataManager::GetValue(TW_SIGNED_ZIP_VERIFY_VAR, zip_verify);
#endif

	DataManager::SetProgress(0);
	if (twrpDigestDriver::Verify_GUI_Digest_Status())
	return check_property_workspace();
	MemMapping map;
#ifdef USE_MINZIP
	if (sysMapFile(path, &map) != 0) {
#else
	if (!map.MapFile(path)) {
#endif
		gui_msg(Msg(msg::kError, "fail_sysmap=Failed to map file '{1}'")(path));
		return -1;
	}

	if (zip_verify) {
		gui_msg("verify_zip_sig=Verifying zip signature...");
#ifdef USE_OLD_VERIFIER
		ret_val = verify_file(map.addr, map.length);
#else
		std::vector<Certificate> loadedKeys;
		if (!load_keys("/res/keys", loadedKeys)) {
			LOGINFO("Failed to load keys");
			gui_err("verify_zip_fail=Zip signature verification failed!");
			set_miui_install_status(OTA_VERIFY_FAIL, true);
#ifdef USE_MINZIP
			sysReleaseMap(&map);
#endif
			return -1;
		}
		ret_val = verify_file(map.addr, map.length, loadedKeys, std::bind(&DataManager::SetProgress, std::placeholders::_1));
#endif
		if (ret_val != VERIFY_SUCCESS) {
			LOGINFO("Zip signature verification failed: %i\n", ret_val);
			gui_err("verify_zip_fail=Zip signature verification failed!");
			set_miui_install_status(OTA_VERIFY_FAIL, true);
#ifdef USE_MINZIP
			sysReleaseMap(&map);
#endif
			return -1;
		} else {
			gui_msg("verify_zip_done=Zip signature verified successfully.");
		}
	
}

	
	ZipWrap Zip;
	if (!Zip.Open(path, &map)) {
		set_miui_install_status(OTA_CORRUPT, true);
		gui_err("zip_corrupt=Zip file is corrupt!");
#ifdef USE_MINZIP
			sysReleaseMap(&map);
#endif
		return INSTALL_CORRUPT;
	}
	
	time_t start, stop;
	time(&start);
	if (Zip.EntryExists(ASSUMED_UPDATE_BINARY_NAME)) {
		LOGINFO("Update binary zip\n");
		// Additionally verify the compatibility of the package.
		if (!verify_package_compatibility(&Zip)) {
			gui_err("zip_compatible_err=Zip Treble compatibility error!");
			Zip.Close();
#ifdef USE_MINZIP
			sysReleaseMap(&map);
#endif
			ret_val = INSTALL_CORRUPT;
		} else {
			ret_val = Prepare_Update_Binary(path, &Zip, wipe_cache);
			if (ret_val == INSTALL_SUCCESS)
				ret_val = Run_Update_Binary(path, &Zip, wipe_cache, UPDATE_BINARY_ZIP_TYPE);
				else
				zip_survival_failed = true;
				if (ret_val != INSTALL_SUCCESS)
				   zip_survival_failed = true;
		}
	} else {
		if (Zip.EntryExists(AB_OTA)) {
			LOGINFO("AB zip\n");
			ret_val = Run_Update_Binary(path, &Zip, wipe_cache, AB_OTA_ZIP_TYPE);
		} else {
				Zip.Close();
				ret_val = INSTALL_CORRUPT;
		}
	}
	time(&stop);
	int total_time = (int) difftime(stop, start);
	if (ret_val == INSTALL_CORRUPT) {
		set_miui_install_status(OTA_CORRUPT, true);
		gui_err("invalid_zip_format=Invalid zip file format!");
	       } else {
		if (DataManager::GetIntValue(RW_INCREMENTAL_PACKAGE) != 0 && zip_is_survival_trigger) {
		if (storage_is_encrypted()) {
        set_miui_install_status(OTA_CORRUPT, false);
        gui_err("wolf_survival_encrypted_err=Internal storage is encrypted! Please do decrypt first!");
        return INSTALL_ERROR;
        }	
	    if ((zip_is_rom_package && !zip_survival_failed) || (zip_is_for_specific_build && !zip_survival_failed))  {
	     std::string survival_folder = get_survival_path();
		if (TWFunc::Path_Exists(survival_folder))
		TWFunc::removeDir(survival_folder, false);
        gui_msg(Msg(msg::kProcess, "wolf_run_process=Starting '{1}' process")("OTA_BAK"));
        DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 1);
		if (PartitionManager.Run_Custom_Backup()) {
		gui_msg(Msg(msg::kProcess, "wolf_run_process_done=Finished '{1}' process")("OTA_BAK"));
		DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 0);
             } else {
        set_miui_install_status(OTA_ERROR, false);
        DataManager::SetValue(RW_RUN_SURVIVAL_BACKUP, 0);
		gui_msg(Msg(msg::kProcess, "wolf_run_process_fail=Unable to finish '{1}' process")("OTA_BAK"));
	    return INSTALL_ERROR;
	      }	
       }    
	}
	      LOGINFO("Install took %i second(s).\n", total_time);
	}
#ifdef USE_MINZIP
	sysReleaseMap(&map);
#endif
	return ret_val;
}
																       	    																			 	 						    																  												