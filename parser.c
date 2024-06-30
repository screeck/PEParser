#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>

void displayErrorMessage(DWORD errorCode) {
    LPSTR messageBuffer = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL);

    if (messageBuffer != NULL) {
        printf("Error: %s\n", messageBuffer);
        LocalFree(messageBuffer);
    }
    else {
        printf("Error: Unable to get error message for code %d\n", errorCode);
    }
}

void printDosHeader(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    printf("----------- DOS HEADER -----------\n");
    printf("WORD e_magic -> 0x%x\n", dosHeader->e_magic);
    printf("WORD e_cblp -> 0x%x\n", dosHeader->e_cblp);
    printf("WORD e_cp -> 0x%x\n", dosHeader->e_cp);
    printf("WORD e_crlc -> 0x%x\n", dosHeader->e_crlc);
    printf("WORD e_cparhdr -> 0x%x\n", dosHeader->e_cparhdr);
    printf("WORD e_minalloc -> 0x%x\n", dosHeader->e_minalloc);
    printf("WORD e_maxalloc -> 0x%x\n", dosHeader->e_maxalloc);
    printf("WORD e_ss -> 0x%x\n", dosHeader->e_ss);
    printf("WORD e_sp -> 0x%x\n", dosHeader->e_sp);
    printf("WORD e_csum -> 0x%x\n", dosHeader->e_csum);
    printf("WORD e_ip -> 0x%x\n", dosHeader->e_ip);
    printf("WORD e_cs -> 0x%x\n", dosHeader->e_cs);
    printf("WORD e_lfarlc -> 0x%x\n", dosHeader->e_lfarlc);
    printf("WORD e_ovno -> 0x%x\n", dosHeader->e_ovno);
    printf("WORD e_oemid -> 0x%x\n", dosHeader->e_oemid);
    printf("WORD e_oeminfo -> 0x%x\n", dosHeader->e_oeminfo);
    printf("LONG e_lfanew -> 0x%x\n", dosHeader->e_lfanew);
}

void printNTHeaders(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    printf("\n");
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    printf("----------- SIGNATURE HEADER -----------\n");
    printf("DWORD Signature -> %x\n", imageNTHeaders->Signature);

    printf("\n");
    printf("----------- FILE HEADER -----------\n");
    printf("WORD Machine -> %x\n", imageNTHeaders->FileHeader.Machine);
    printf("WORD NumberOfSections -> %x\n", imageNTHeaders->FileHeader.NumberOfSections);
    printf("DWORD TimeDateStamp -> %x\n", imageNTHeaders->FileHeader.TimeDateStamp);
    printf("DWORD PointerToSymbolTable -> %x\n", imageNTHeaders->FileHeader.PointerToSymbolTable);
    printf("DWORD NumberOfSymbols -> %x\n", imageNTHeaders->FileHeader.NumberOfSymbols);
    printf("WORD SizeOfOptionalHeader -> %x\n", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
    printf("WORD Characteristics -> %x\n", imageNTHeaders->FileHeader.Characteristics);

    printf("\n");
    printf("----------- OPTIONAL HEADER -----------\n");
    printf("WORD Magic -> %x\n", imageNTHeaders->OptionalHeader.Magic);
    printf("BYTE MajorLinkerVersion -> %x\n", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
    printf("BYTE MinorLinkerVersion -> %x\n", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
    printf("DWORD SizeOfCode -> %x\n", imageNTHeaders->OptionalHeader.SizeOfCode);
    printf("DWORD SizeOfInitializedData -> %x\n", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
    printf("DWORD SizeOfUninitializedData -> %x\n", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
    printf("DWORD AddressOfEntryPoint -> %x\n", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("DWORD BaseOfCode -> %x\n", imageNTHeaders->OptionalHeader.BaseOfCode);
    printf("DWORD ImageBase -> %x\n", imageNTHeaders->OptionalHeader.ImageBase);
    printf("DWORD SectionAlignment -> %x\n", imageNTHeaders->OptionalHeader.SectionAlignment);
    printf("DWORD FileAlignment -> %x\n", imageNTHeaders->OptionalHeader.FileAlignment);
    printf("WORD MajorOperatingSystemVersion -> %x\n", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
    printf("WORD MinorOperatingSystemVersion -> %x\n", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
    printf("WORD MajorImageVersion -> %x\n", imageNTHeaders->OptionalHeader.MajorImageVersion);
    printf("WORD MinorImageVersion -> %x\n", imageNTHeaders->OptionalHeader.MinorImageVersion);
    printf("WORD MajorSubsystemVersion -> %x\n", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
    printf("WORD MinorSubsystemVersion -> %x\n", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
    printf("DWORD Win32VersionValue -> %x\n", imageNTHeaders->OptionalHeader.Win32VersionValue);
    printf("DWORD SizeOfImage -> %x\n", imageNTHeaders->OptionalHeader.SizeOfImage);
    printf("DWORD SizeOfHeaders -> %x\n", imageNTHeaders->OptionalHeader.SizeOfHeaders);
    printf("DWORD CheckSum -> %x\n", imageNTHeaders->OptionalHeader.CheckSum);
    printf("WORD Subsystem -> %x\n", imageNTHeaders->OptionalHeader.Subsystem);
    printf("WORD DllCharacteristics -> %x\n", imageNTHeaders->OptionalHeader.DllCharacteristics);
    printf("DWORD SizeOfStackReserve -> %x\n", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
    printf("DWORD SizeOfStackCommit -> %x\n", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
    printf("DWORD SizeOfHeapReserve -> %x\n", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
    printf("DWORD SizeOfHeapCommit -> %x\n", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
    printf("DWORD LoaderFlags -> %x\n", imageNTHeaders->OptionalHeader.LoaderFlags);
    printf("DWORD NumberOfRvaAndSizes -> %x\n", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);
}

void printDataDirectories(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);

    printf("\n");
    printf("----------- DATA DIRECTORIES  -----------\n");
    printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
    printf("\tImport Directory Address: 0x%x; Size: 0x%x\n", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[1].Size);
}

void printSectionHeaders(LPVOID fileData) {
    printf("\n");
    printf("----------- SECTION HEADERS  -----------\n");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)imageNTHeaders +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        imageNTHeaders->FileHeader.SizeOfOptionalHeader);

    DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
        printf("\t%s\n", sectionHeader->Name);  //Access violation reading location
        printf("VirtualSize -> %x\n", sectionHeader->Misc.VirtualSize);
        printf("VirtualAddress -> %x\n", sectionHeader->VirtualAddress);
        printf("SizeOfRawData -> %x\n", sectionHeader->SizeOfRawData);
        printf("PointerToRawData -> %x\n", sectionHeader->PointerToRawData);
        printf("PointerToRelocations -> %x\n", sectionHeader->PointerToRelocations);
        printf("PointerToLinenumbers -> %x\n", sectionHeader->PointerToLinenumbers);
        printf("NumberOfRelocations -> %x\n", sectionHeader->NumberOfRelocations);
        printf("NumberOfLinenumbers -> %x\n", sectionHeader->NumberOfLinenumbers);
        printf("Characteristics -> %x\n", sectionHeader->Characteristics);

        // Save section that contains import directory table
        if (importDirectoryRVA >= sectionHeader->VirtualAddress &&
            importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
            PIMAGE_SECTION_HEADER importSection = sectionHeader;
        }

        // Move to the next section header
        sectionHeader++;
    }
}

void printMenu() {
    printf("\n");
    printf("---Options---\n");
    printf("DosHeader -> 1\n");
    printf("NTHeaders -> 2\n");
    printf("DataDirectories -> 3\n");
    printf("SectionHeaders -> 4\n");
    printf("Exit -> 5\n");
    printf("What do you wanna see?: ");
}

int main(int argc, char* argv[]) {


    char fileName[MAX_PATH];
    int option = -1;

    printf("-----------PE Parser----------- \n");
    printf("Give me the file path: ");
    scanf("%s", fileName);
    printMenu();
    
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening file... \n");
        printf("[-] Error message: ");
        displayErrorMessage(GetLastError());
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting file size... \n");
        printf("[-] Error message: ");
        displayErrorMessage(GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (fileData == NULL) {
        printf("[-] Error allocating memory... \n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        printf("[-] Error reading file... \n");
        printf("[-] Error message: ");
        displayErrorMessage(GetLastError());
        HeapFree(GetProcessHeap(), 0, fileData);
        CloseHandle(hFile);
        return 1;
    }


    while (option != 5) {
        scanf("%d", &option);
        switch (option){
        case 1:
            printDosHeader(fileData);
            break;
        
        case 2:
            printNTHeaders(fileData);
            break;

        case 3:
            printDataDirectories(fileData);
            break;

        case 4:
            printSectionHeaders(fileData);
            break;
        
        case 5:
            printf("Exitting...");
            return 0;
        }
        printMenu();
    }


   
    HeapFree(GetProcessHeap(), 0, fileData);
    CloseHandle(hFile);
    return 0;
}
