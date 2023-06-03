#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <string>
#include <array>
#include <vector>
#include <shellapi.h>
#include <cstdlib>
#include <ctime>
//#include <stdio.h>

using namespace std;
bool error_b = false;
char* error_c = NULL;
void Get_Registers_State(CONTEXT* cont, const char* error, HANDLE hProcess)
{
    FILE* F = fopen("result.txt", "a");
    fprintf(F, "Exception: %s\n", error);
    fprintf(F, "EAX : 0x%p ESP : 0x%p\n", (void*)cont->Eax, (void*)cont->Esp);
    fprintf(F, "EBX : 0x%p EBP : 0x%p\n", (void*)cont->Ebx, (void*)cont->Ebp);
    fprintf(F, "ECX : 0x%p EDI : 0x%p\n", (void*)cont->Ecx, (void*)cont->Edi);
    fprintf(F, "EDX : 0x%p ESI : 0x%p\n", (void*)cont->Edx, (void*)cont->Esi);
    fprintf(F, "EIP : 0x%p FLG : 0x%p\n", (void*)cont->Eip, (void*)cont->EFlags);
    // читаем из памяти по указателю на вершину стека (ESP) 
    unsigned char buffer[4048] = { 0 };
    SIZE_T recvSize = 0;
    //ReadProcessMemory(hProcess, (void*)cont->Esp, buffer, sizeof(buffer), &recvSize);

    if (ReadProcessMemory(hProcess, (void*)cont->Esp, buffer, sizeof(buffer), &recvSize)/*recvSize*/ != 0)
    {
        cout << "Stack: " << recvSize << " bytes read" << std::endl;

        fprintf(F, "\nStack (%d bytes read):\n", recvSize);

        for (int i = 0; i < recvSize; i++)
        {
            if ((i + 1) % 4 == 1)
            {
                fprintf(F, "0x%p : ", (void*)((char*)cont->Esp + i));
            }

            if (buffer[i] < 0x10)
            {
                fprintf(F, "0");
            }

            fprintf(F, "%X ", (int)buffer[i]);


            if ((i + 1) % 4 == 0)
            {
                fprintf(F, "\n");
            }
        }
    }
    else
    {
        cout << "ReadProcessMemory failed: " << GetLastError() << endl;
    }

    fprintf(F, "--------------------------------\n\n");
    fclose(F);

}

void Run_program()
{
    HANDLE thread;
    PROCESS_INFORMATION proc_info;
    STARTUPINFO startup_info;
    BOOL status;
    CONTEXT cont;

    DEBUG_EVENT debug_event = { 0 };
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    const char* tmp = "config_4";
    LPSTR cmdArgs = const_cast<LPSTR>(tmp);;
    status = CreateProcessA((LPCSTR)"F:\\Microsoft Visual Studio\\repos\\MBKS1\\vuln4.exe", cmdArgs, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, (LPSTARTUPINFOA)&startup_info, &proc_info);
    if (status == false)
    {
        std::cout << "CreateProcess failed: " << std::dec << GetLastError() << std::endl;
        return;
    }
    while (true)
    {
        // ожидаем событие отладки 
        status = WaitForDebugEvent(&debug_event, 500);
        if (status == false)
        {
            if (GetLastError() != ERROR_SEM_TIMEOUT)
                std::cout << "WaitForDebugEvent failed: " << std::dec << GetLastError() << std::endl;
            break;
        }

        // смотрим код события 
        if (debug_event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
        {
            // если это не исключение - продолжаем ожидать 
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            continue;
        }
        thread = OpenThread(THREAD_ALL_ACCESS, FALSE, debug_event.dwThreadId);
        if (thread == NULL)
        {
            std::cout << "OpenThread failed: " << std::dec << GetLastError() << std::endl;
            break;
        }
        cont.ContextFlags = CONTEXT_FULL;

        // по хэндлу получаем его контекст 
        status = GetThreadContext(thread, &cont);
        if (status == false)
        {
            cout << "GetThreadContext failed: " << dec << GetLastError() << endl;
            CloseHandle(thread);
            break;
        }
        switch (debug_event.u.Exception.ExceptionRecord.ExceptionCode)
        {
        case EXCEPTION_ACCESS_VIOLATION:
            Get_Registers_State(&cont, "EXCEPTION_ACCESS_VIOLATION", proc_info.hProcess);
            error_b = true;
            break;
        //case EXCEPTION_BREAKPOINT:
            //Get_Registers_State(&cont, "EXCEPTION_BREAKPOINT", proc_info.hProcess);
            //error_b = true;
           // break;
        case EXCEPTION_STACK_OVERFLOW:
            Get_Registers_State(&cont, "EXCEPTION_STACK_OVERFLOW", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            Get_Registers_State(&cont, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            Get_Registers_State(&cont, "EXCEPTION_DATATYPE_MISALIGNMENT", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            Get_Registers_State(&cont, "EXCEPTION_FLT_DENORMAL_OPERAND", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            Get_Registers_State(&cont, "EXCEPTION_FLT_DIVIDE_BY_ZERO", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            Get_Registers_State(&cont, "EXCEPTION_FLT_INEXACT_RESULT", proc_info.hProcess); \
                error_b = true;
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            Get_Registers_State(&cont, "EXCEPTION_FLT_INVALID_OPERATION", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_OVERFLOW:
            Get_Registers_State(&cont, "EXCEPTION_FLT_OVERFLOW", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            Get_Registers_State(&cont, "EXCEPTION_FLT_STACK_CHECK", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            Get_Registers_State(&cont, "EXCEPTION_FLT_UNDERFLOW", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            Get_Registers_State(&cont, "EXCEPTION_ILLEGAL_INSTRUCTION", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            Get_Registers_State(&cont, "EXCEPTION_IN_PAGE_ERROR", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            Get_Registers_State(&cont, "EXCEPTION_INT_DIVIDE_BY_ZERO", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_INT_OVERFLOW:
            Get_Registers_State(&cont, "EXCEPTION_INT_OVERFLOW", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            Get_Registers_State(&cont, "EXCEPTION_INVALID_DISPOSITION", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            Get_Registers_State(&cont, "EXCEPTION_NONCONTINUABLE_EXCEPTION", proc_info.hProcess);
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            Get_Registers_State(&cont, "EXCEPTION_PRIV_INSTRUCTION", proc_info.hProcess);
            error_b = true;
            break;
        case EXCEPTION_SINGLE_STEP:
            Get_Registers_State(&cont, "EXCEPTION_SINGLE_STEP", proc_info.hProcess);
            error_b = true;
            break;

        default:
            cout << "Unknown exception: " << dec << debug_event.u.Exception.ExceptionRecord.ExceptionCode << endl;
            ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
        }
    }

    CloseHandle(proc_info.hProcess);

}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

void ErrorHandler(char* config, int size) {
    if (config != NULL) {
        FILE* open = fopen("breaking_config.txt", "w");
        for (int i = 0; i < size; i++) {
            fputc(config[i], open);
        }
        fclose(open);
    }
    exit(-1);
}

void ExecuteApplication(char* config = NULL, int size = 0) {
    Run_program();
    if (error_b == true) {
        ErrorHandler(config, size);
    }
    //cout<<exec("vuln4.exe");
}


long int CreateValue(int power) {
    long int value= 0xFF;
    for (int i = 0; i < power; i++) {
        value = value << 8;
        value += 0xFF;
    }
    return value;
}

void OutputConfig(char* config, int size) {
    std::cout << "Config:";
    for (int i = 0; i < size; i++) {
       /* if (config[i] == 0) {
            std::cout << '0';
        }
        else {
            std::cout << std::hex << int(config[i]);
        }*/
        printf("%X-", (unsigned char)config[i]);
    }
}

void WriteNewConfig(int size, char* variable_config) {
    FILE* config_file;
    config_file = fopen("config_4", "wb+");
    for (int i = 0; i < size; i++) {
        fputc(variable_config[i], config_file);
    }
    fclose(config_file);
}

void WriteAndRun(int start, int end,int j, char* variable_config, char* value_ptr, int size) {
    for (int i = start; i < end-1; i += j) {
        if (j + i < end) {
            if (j > 1) {
                value_ptr += (j);
                for (int k = 0; k < j; k++) {
                    value_ptr--;
                    memcpy(&variable_config[i+k], value_ptr, 1);
                }
            }
            else {
                memcpy(&variable_config[i], value_ptr, j);
            }
        }
        WriteNewConfig(size, variable_config);
        ExecuteApplication(variable_config,size);
        //OutputConfig(variable_config, size);
    }
}

void LimitValues(int start, int end, int power, char* config, int size) {
    char* variable_config = new char[(size) * sizeof(char)];
    long int value=0, tmp = 0;
    char* value_ptr = (char*)&value;
    for (int j = 0; j < power; j++) {
        tmp = CreateValue(j);
        for (int type = 0; type < 5; type++) {
            switch (type)
            {
            case 0:
                value = tmp;
                if (j > 0) {
                    continue;
                }
                break;
            case 1:
                value = 0;
                if (j > 0) {
                    continue;
                }
                break;
            case 2:
                value = tmp/2;
                break;
            case 3:
                value = tmp / 2 + 1;
                break;
            case 4:
                value = tmp / 2 - 1;
                break;
            default:
                break;
            }
            //printf("\n========================<<%d>>========================",type);
            memcpy(variable_config, config, size);
            WriteAndRun(start, end, j+1, variable_config, value_ptr, size);
        }
        //value_ptr++;
    }
    delete[] variable_config;
}

void AimedChange(int start, int end, int power, char* config, int size) {
    int variant = 0;
    while (1) {
        std::cout << "Random change?\n1)Yes\n2)no\n";
        std::cin >> variant;
        if (variant == 1 || variant == 2) {
            break;
        }
    }
    switch (variant)
    {
    case 1:
        srand(time(0));
        for (int i = start; i < end; i++) {
            config[i] = rand() % 255;
        }
        break;
    case 2:
        std::cout << "Please enter" << end-start<< " symbols:\n";
        for (int i = start; i < end; i++) {
            std::cin>>config[i];
        }
        break;
    default:
        break;
    }
    WriteNewConfig(size,config);
    ExecuteApplication();
}

void ReturnConfig() {
    DeleteFile(L"F:\\Microsoft Visual Studio\\repos\\MBKS1\\config_4");
    CopyFile(L"E:\\Desktop\\MBKS\\Lab1\\vulns1\\config_4", L"F:\\Microsoft Visual Studio\\repos\\MBKS1\\config_4", 1);
}

char* Init(int* size) {
    ReturnConfig();
    FILE* config_file = fopen("config_4", "r");
    fseek(config_file, 0, SEEK_END);
    *size = ftell(config_file);
    char* config = new char[(*size) * sizeof(char)];
    fseek(config_file, 0, SEEK_SET); //возврат на начало
    fread(config, sizeof(char), *size, config_file);
    fclose(config_file);
    //OutputConfig(config, *size);
    ExecuteApplication();
    return config;
}

void LookingDivisionSymbols(int size, char* config) {
    bool flag = 0;
    char tokens[] = ",;:=";
    int amount_of_tokens = sizeof(tokens) / sizeof(char);
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < amount_of_tokens-1; j++) {
            if (config[i] == tokens[j]) {
                std::cout << "Find:" << tokens[j] << std::endl;
                flag = 1;
            }
        }
    }
    if (flag == 0) {
        std::cout << "Find noting";
    }
}

void AddNewEnd(int size, char* config) {
    int variant = 0, new_size = 0;
    std::string new_symbols, symbol;
    char* new_config = NULL;
    while (1) {
        std::cout << "Add random change?\n1)Yes\n2)no\n";
        std::cin >> variant;
        if (variant == 1 || variant == 2) {
            break;
        }
    }
    switch (variant)
    {
    case 1:
        std::cout << "How many?";
        std::cin >> new_size;
        srand(time(0));
        for (int i = 0; i < new_size; i++) {
            symbol = char(rand() % 255);
            new_symbols.append(symbol);
        }
        break;
    case 2:
        std::cout << "Please enter new symbols:\n";
        std::cin >> new_symbols;
        break;
    default:
        break;
    }
    new_size = new_symbols.length();
    new_config = new char[size + new_size];
    memcpy(new_config, config, size); // на место конца строки
    memcpy(&new_config[size-1], new_symbols.c_str(), new_size+1);
    WriteNewConfig(size+ new_size, new_config);
    ExecuteApplication();
    delete[] new_config;
}

int main()
{
    int variant = 0, start = 0, end = 0, size = 0, power = 0, new_size = 0;
    char* config = NULL;
    while (1) {
        config = Init(&size);
        std::cout << "What to do:\n1)Auto Fuzzing\n2)Aimed change\n3)Find division symbols\n4)Expand the size of config\n5)Init\n";
        std::cin >> variant;
        switch (variant)
        {
        case 1:
            std::cout << "Enter start (min 0) :";
            std::cin >> start;
            if (start < 0) {
                start = 0;
            }
            std::cout << "\nEnter end (max "<< size << "):";
            std::cin >> end;
            if (end > size) {
                end = size;
            }
            std::cout << "\nEnter power (min 0):";
            std::cin >> power;
            if (config != NULL) {
                LimitValues(start, end, power, config, size); // 54 
            }
            break;
        case 2:
            std::cout << "Enter start (min 0) :";
            std::cin >> start;
            if (start < 0) {
                start = 0;
            }
            std::cout << "\nEnter end (max " << size << "):";
            std::cin >> end;
            if (end > size) {
                end = size;
            }
            if (config != NULL) {
                AimedChange(start, end, power, config, size); // 54 
            }
            break;
        case 3:
            LookingDivisionSymbols(size, config);
            break;
        case 4:
            AddNewEnd(size, config);
            break;
        case 5:
            break;
        default:
            std::cout << "Incorrect value!\n";
            break;
        }
        std::cout << std::endl;
       // ExecuteApplication();
        //LimitValues(0, end, 4, config); // 54 
    }
    delete[] config;
}
