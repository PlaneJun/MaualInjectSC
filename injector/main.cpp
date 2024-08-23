// injector.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#include "../MaunalInjectSC/inject_sc.h"
#include "test_dll.h"

struct InjectParams
{
   PVOID ptr; // mmap后Dll的位置
   PVOID dll; // 写过去Dll文件的位置
   SIZE_T dll_size; // dll大小
   BOOL is_done;
};

int inject(uint32_t pid)
{
   HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
   if (!hProc)
   {
      printf("open process failed,err:%d\n", GetLastError());
      return 0;
   }

   // 写dll
   PVOID lpDllMem = VirtualAllocEx(hProc, NULL, sizeof(hexData), MEM_COMMIT, PAGE_READWRITE);
   if (lpDllMem)
   {
      WriteProcessMemory(hProc, lpDllMem, hexData, sizeof(hexData), NULL);
   }
   else
   {
      printf("alloc dll data failed,err:%d\n", GetLastError());
      return 0;
   }

   // 写参数
   PVOID lpParam = VirtualAllocEx(hProc, NULL, sizeof(InjectParams), MEM_COMMIT, PAGE_READWRITE);
   if (lpParam)
   {
      InjectParams p{};
      p.dll = lpDllMem;
      p.dll_size = sizeof(hexData);
      WriteProcessMemory(hProc, lpParam, &p, sizeof(InjectParams), NULL);
   }
   else
   {
      printf("alloc dll param failed,err:%d\n", GetLastError());
      VirtualFreeEx(hProc, lpDllMem, sizeof(hexData), MEM_DECOMMIT);
      return 0;
   }

   // 写shellcode
   PVOID lpInjectSC = VirtualAllocEx(hProc, NULL, sizeof(inject_sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
   if (lpInjectSC)
   {
      WriteProcessMemory(hProc, lpInjectSC, inject_sc, sizeof(inject_sc), NULL);
      CreateRemoteThread(hProc, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpInjectSC), lpParam, NULL, NULL);

      InjectParams status{};
      while (true)
      {
         ReadProcessMemory(hProc, lpParam, &status, sizeof(InjectParams), NULL);
         if (status.is_done)
         {
            printf("inject ok,ptr = %p\n", status.ptr);

            break;
         }
      }
   }
   else
   {
      printf("alloc x64_inject_sc mem failed,err:%d\n", GetLastError());
   }

   VirtualFreeEx(hProc, lpParam, sizeof(InjectParams), MEM_DECOMMIT);
   VirtualFreeEx(hProc, lpInjectSC, sizeof(inject_sc), MEM_DECOMMIT);
   VirtualFreeEx(hProc, lpDllMem, sizeof(hexData), MEM_DECOMMIT);
}

int main()
{
   inject(30596);


   return 0;
}
