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

#ifndef _RWRPDUMWOLF_HPP
#define _RWRPDUMWOLF_HPP

#include <string>
#include <vector>

using namespace std;

class RWDumwolf
{
public:
    static bool Repack_Image(string mount_point);
    static bool Unpack_Image(string mount_point);
	static void Deactivation_Process(void);
	static bool Resize_By_Path(string path);
	static void Read_Write_Specific_Partition(string path, string partition_name, bool backup);
private:
	static bool Patch_Forced_Encryption();
    static bool Patch_DM_Verity();
    static string Load_File(string extension);
    static void Set_New_Ramdisk_Property(string prop, bool enable);
};

#endif
