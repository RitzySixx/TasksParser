import webview
import os
import sys
import ctypes
from ctypes import wintypes, POINTER, byref, create_unicode_buffer
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import pythoncom
import win32com.client
import xml.etree.ElementTree as ET
import winreg
import re
import time

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)]

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(GUID))]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD),
                ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD)]

WTD_UI_NONE = 2
WTD_CHOICE_FILE = 1
WTD_REVOKE_NONE = 0
WTD_STATEACTION_IGNORE = 0
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(0xaac56b, 0xcd44, 0x11d0, (0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))

wintrust = ctypes.windll.wintrust

class TaskScanner:
    def __init__(self):
        self.results = []
        self.is_scanning = False
        self.thread_pool = ThreadPoolExecutor(max_workers=8)

    def check_file_signature(self, file_path):
        if not file_path or file_path == "N/A" or not os.path.exists(file_path):
            return "deleted"
        if os.path.isdir(file_path):
            return "unsigned"
        try:
            file_info = WINTRUST_FILE_INFO()
            file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
            file_info.pcwszFilePath = file_path
            file_info.hFile = None
            file_info.pgKnownSubject = None
            data = WINTRUST_DATA()
            data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
            data.pPolicyCallbackData = None
            data.pSIPClientData = None
            data.dwUIChoice = WTD_UI_NONE
            data.fdwRevocationChecks = WTD_REVOKE_NONE
            data.dwUnionChoice = WTD_CHOICE_FILE
            data.pFile = ctypes.addressof(file_info)
            data.dwStateAction = WTD_STATEACTION_IGNORE
            data.hWVTStateData = None
            data.pwszURLReference = None
            data.dwProvFlags = 0
            data.dwUIContext = 0
            result_code = wintrust.WinVerifyTrust(
                wintypes.HWND(0),
                ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(data)
            )
            if result_code == 0:
                return "valid"
            else:
                return self._check_catalog_signature(file_path)
        except Exception as e:
            return self._check_catalog_signature(file_path)

    def _check_catalog_signature(self, file_path):
        try:
            cryptcatadmin = ctypes.windll.wintrust
            CryptCATAdminAcquireContext2 = cryptcatadmin.CryptCATAdminAcquireContext2
            CryptCATAdminAcquireContext2.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminAcquireContext2.restype = wintypes.BOOL
            CryptCATAdminReleaseContext = cryptcatadmin.CryptCATAdminReleaseContext
            CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminReleaseContext.restype = wintypes.BOOL
            CryptCATAdminCalcHashFromFileHandle2 = cryptcatadmin.CryptCATAdminCalcHashFromFileHandle2
            CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
            CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
            CryptCATAdminEnumCatalogFromHash = cryptcatadmin.CryptCATAdminEnumCatalogFromHash
            CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
            CryptCATCatalogInfoFromContext = cryptcatadmin.CryptCATCatalogInfoFromContext
            CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
            CryptCATAdminReleaseCatalogContext = cryptcatadmin.CryptCATAdminReleaseCatalogContext
            CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
            CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
            
            file_handle = ctypes.windll.kernel32.CreateFileW(
                file_path, 
                0x80000000,
                1,
                None, 
                3,
                0, 
                None
            )
            if file_handle == wintypes.HANDLE(-1).value:
                return "unsigned"
            try:
                hCatAdmin = wintypes.HANDLE()
                if not CryptCATAdminAcquireContext2(ctypes.byref(hCatAdmin), None, None, None, 0):
                    return "unsigned"
                try:
                    hash_size = wintypes.DWORD(100)
                    hash_buffer = (ctypes.c_byte * hash_size.value)()
                    if not CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file_handle, ctypes.byref(hash_size), hash_buffer, 0):
                        return "unsigned"
                    hPrevCat = wintypes.HANDLE()
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash_buffer, hash_size.value, 0, ctypes.byref(hPrevCat))
                    if hCatInfo:
                        catalog_info = ctypes.create_string_buffer(1024)
                        if CryptCATCatalogInfoFromContext(hCatInfo, catalog_info, 1024):
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                            return "valid"
                        else:
                            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0)
                            return "unsigned"
                    else:
                        return "unsigned"
                finally:
                    CryptCATAdminReleaseContext(hCatAdmin, 0)
            finally:
                ctypes.windll.kernel32.CloseHandle(file_handle)
        except Exception as e:
            return "unsigned"

    def _extract_executable_path(self, command):
        if not command:
            return ""
        
        command = command.strip()
        
        if command.startswith('"') and '"' in command[1:]:
            end_quote = command.find('"', 1)
            if end_quote != -1:
                path = command[1:end_quote]
                if '.' in os.path.basename(path):
                    return path
                elif os.path.exists(path + '.exe'):
                    return path + '.exe'
                else:
                    return path
        
        executable_extensions = ['.exe', '.dll', '.com', '.bat', '.ps1', '.vbs', '.js', '.msi', '.scr', '.pif']
        
        for ext in executable_extensions:
            if ext in command.lower():
                ext_pos = command.lower().find(ext)
                if ext_pos != -1:
                    potential_path = command[:ext_pos + len(ext)]
                    if (potential_path.startswith(('C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:')) or
                        '\\' in potential_path or '/' in potential_path):
                        return potential_path
        
        path_patterns = [
            r'[A-Za-z]:[\\/][^\\/].*?\.(exe|dll|com|bat|ps1|vbs|js|msi|scr|pif)',
            r'\\\\[^\\/]+[\\/].*?\.(exe|dll|com|bat|ps1|vbs|js|msi|scr|pif)',
            r'%[^%]+%.*?\.(exe|dll|com|bat|ps1|vbs|js|msi|scr|pif)',
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, command, re.IGNORECASE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    return match
        
        parts = command.split()
        if parts:
            first_part = parts[0]
            if '.' in first_part and any(first_part.lower().endswith(ext) for ext in executable_extensions):
                return first_part
            elif first_part.lower() in ['schtasks', 'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 
                                      'rundll32', 'regsvr32', 'msbuild', 'installutil', 'bitsadmin', 
                                      'certutil', 'wmic', 'sc', 'net']:
                return first_part + '.exe'
            else:
                return first_part
        
        return ""

    def _resolve_path(self, command, working_dir):
        if not command:
            return ""
        
        exe_path = self._extract_executable_path(command)
        
        if not exe_path:
            return ""
        
        try:
            exe_path = os.path.expandvars(exe_path)
        except:
            pass
        
        if os.path.isabs(exe_path) and os.path.exists(exe_path):
            return exe_path
        
        if working_dir:
            working_dir = os.path.expandvars(working_dir)
            if os.path.isabs(working_dir):
                potential_path = os.path.join(working_dir, exe_path)
                if os.path.exists(potential_path):
                    return potential_path
        
        system_dirs = [
            os.environ.get('SystemRoot', 'C:\\Windows'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\WindowsPowerShell\\v1.0'),
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
            os.environ.get('TEMP', 'C:\\Windows\\Temp'),
            os.environ.get('TMP', 'C:\\Windows\\Temp'),
            os.environ.get('USERPROFILE', 'C:\\Users\\Default'),
        ]
        
        path_dirs = os.environ.get('PATH', '').split(';')
        system_dirs.extend(path_dirs)
        
        for sys_dir in system_dirs:
            if sys_dir and os.path.exists(sys_dir):
                potential_path = os.path.join(sys_dir, exe_path)
                if os.path.exists(potential_path):
                    return potential_path
                if exe_path.endswith('.exe'):
                    potential_path_no_ext = os.path.join(sys_dir, exe_path[:-4])
                    if os.path.exists(potential_path_no_ext):
                        return potential_path_no_ext
        
        return exe_path

    def _parse_task_xml(self, xml_content):
        command = ""
        arguments = ""
        on_logon = "No"
        working_dir = ""
        source = ""
        author = ""
        description = ""
        
        try:
            root = ET.fromstring(xml_content)
            
            ns = {'ns': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
            
            logon_triggers = root.findall('.//ns:Triggers/ns:LogonTrigger', ns)
            if logon_triggers:
                on_logon = "Yes"
            
            boot_triggers = root.findall('.//ns:Triggers/ns:BootTrigger', ns)
            registration_triggers = root.findall('.//ns:Triggers/ns:RegistrationTrigger', ns)
            if boot_triggers or registration_triggers:
                on_logon = "Yes"
            
            actions_elem = root.find('.//ns:Actions', ns)
            if actions_elem is not None:
                exec_elem = actions_elem.find('.//ns:Exec', ns)
                if exec_elem is not None:
                    command_elem = exec_elem.find('ns:Command', ns)
                    if command_elem is not None and command_elem.text:
                        command = command_elem.text
                    
                    arguments_elem = exec_elem.find('ns:Arguments', ns)
                    if arguments_elem is not None and arguments_elem.text:
                        arguments = arguments_elem.text
                    
                    working_dir_elem = exec_elem.find('ns:WorkingDirectory', ns)
                    if working_dir_elem is not None and working_dir_elem.text:
                        working_dir = working_dir_elem.text
            
            registration_info = root.find('.//ns:RegistrationInfo', ns)
            if registration_info is not None:
                source_elem = registration_info.find('ns:Source', ns)
                if source_elem is not None and source_elem.text:
                    source = source_elem.text
                
                author_elem = registration_info.find('ns:Author', ns)
                if author_elem is not None and author_elem.text:
                    author = author_elem.text
                
                description_elem = registration_info.find('ns:Description', ns)
                if description_elem is not None and description_elem.text:
                    description = description_elem.text
                        
        except Exception as e:
            pass
        
        return command, arguments, on_logon, working_dir, source, author, description

    def _extract_path_from_resource(self, resource_text):
        if not resource_text:
            return ""
        
        if resource_text.startswith('$(@') and ')' in resource_text:
            start = resource_text.find('$(@') + 3
            end = resource_text.find(',', start)
            if end == -1:
                end = resource_text.find(')', start)
            if end != -1:
                path_part = resource_text[start:end]
                try:
                    path_part = os.path.expandvars(path_part)
                except:
                    pass
                return path_part
        
        return resource_text

    def _detect_suspicious_patterns(self, task_name, command, arguments, file_path, signature_status):
        detections = []
        
        system_executables = {
            'schtasks.exe', 'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msbuild.exe', 'installutil.exe',
            'bitsadmin.exe', 'certutil.exe', 'wmic.exe', 'sc.exe', 'net.exe'
        }
        
        command_lower = (command + ' ' + (arguments or '')).lower()
        actual_exe = os.path.basename(file_path).lower() if file_path and file_path != "N/A" and os.path.exists(file_path) else ""
        
        for exe in system_executables:
            if exe in command_lower:
                if actual_exe and actual_exe != exe and actual_exe not in system_executables:
                    detections.append("Proxy Execution")
                    break
        
        if self._is_registry_only_task(task_name):
            detections.append("Registry Mismatch Detection - Discovers registry-only tasks without XML files (GhostTask persistence)")
        
        return list(set(detections))

    def _is_registry_only_task(self, task_name):
        try:
            task_found_in_scheduler = False
            
            try:
                scheduler = win32com.client.Dispatch("Schedule.Service")
                scheduler.Connect()
                root_folder = scheduler.GetFolder("\\")
                task = root_folder.GetTask(task_name)
                if task:
                    task_found_in_scheduler = True
            except:
                pass
            
            task_found_in_registry = False
            registry_paths = [
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
            ]
            
            for base_path in registry_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path)
                    try:
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                if task_name in subkey_name:
                                    task_found_in_registry = True
                                    break
                                i += 1
                            except WindowsError:
                                break
                    finally:
                        winreg.CloseKey(key)
                    if task_found_in_registry:
                        break
                except:
                    continue
            
            return task_found_in_registry and not task_found_in_scheduler
            
        except Exception:
            return False

    def get_all_tasks(self):
        pythoncom.CoInitialize()
        tasks = []
        try:
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            
            def get_tasks_from_folder(folder):
                folder_tasks = []
                try:
                    folder_tasks_collection = folder.GetTasks(1)
                    for task in folder_tasks_collection:
                        folder_tasks.append(task)
                except Exception as e:
                    pass
                
                try:
                    folders_collection = folder.GetFolders(0)
                    for subfolder in folders_collection:
                        folder_tasks.extend(get_tasks_from_folder(subfolder))
                except Exception as e:
                    pass
                
                return folder_tasks
            
            root_folder = scheduler.GetFolder("\\")
            tasks = get_tasks_from_folder(root_folder)
            
        except Exception as e:
            pass
        finally:
            pythoncom.CoUninitialize()
        
        return tasks

    def _process_single_task(self, task):
        try:
            task_name = task.Name
            task_path = task.Path
            
            xml_content = task.Xml
            command, arguments, on_logon, working_dir, source, author, description = self._parse_task_xml(xml_content)
            
            resolved_path = self._resolve_path(command, working_dir)
            
            if not resolved_path:
                if source:
                    source_path = self._extract_path_from_resource(source)
                    if source_path:
                        resolved_path = self._resolve_path(source_path, "")
                        if not resolved_path:
                            resolved_path = source_path
                elif author:
                    author_path = self._extract_path_from_resource(author)
                    if author_path:
                        resolved_path = self._resolve_path(author_path, "")
                        if not resolved_path:
                            resolved_path = author_path
                elif description:
                    desc_path = self._extract_path_from_resource(description)
                    if desc_path:
                        resolved_path = self._resolve_path(desc_path, "")
                        if not resolved_path:
                            resolved_path = desc_path
            
            if not resolved_path or resolved_path == "N/A":
                return None
            
            signature_status = self.check_file_signature(resolved_path)
            
            detections = self._detect_suspicious_patterns(
                task_name, command, arguments, resolved_path, signature_status
            )
            
            result = {
                'name': task_name,
                'path': resolved_path,
                'arguments': arguments,
                'signature': signature_status,
                'on_logon': on_logon,
                'detections': detections
            }
            
            return result
            
        except Exception as e:
            return None

    def scan_tasks(self, window):
        self.is_scanning = True
        self.results = []
        
        try:
            window.evaluate_js("clearAllResults();")
            
            tasks = self.get_all_tasks()
            
            if not tasks:
                window.evaluate_js("showError('No tasks found in Task Scheduler.');")
                self.is_scanning = False
                return
            
            total_tasks = len(tasks)
            completed_count = 0
            processed_count = 0
            
            futures = []
            for task in tasks:
                if not self.is_scanning:
                    break
                future = self.thread_pool.submit(self._process_single_task, task)
                futures.append(future)
            
            for future in as_completed(futures):
                if not self.is_scanning:
                    break
                
                try:
                    result = future.result(timeout=10)
                    completed_count += 1
                    
                    if result:
                        self.results.append(result)
                        processed_count += 1
                        window.evaluate_js(f"addResult({json.dumps(result)});")
                    
                    progress = (completed_count / total_tasks) * 100
                    window.evaluate_js(f"updateProgress({progress:.1f}, {processed_count}, {total_tasks});")
                        
                except Exception as e:
                    completed_count += 1
                    
        except Exception as e:
            window.evaluate_js(f"showError('Scanning failed: {str(e)}');")
        finally:
            self.is_scanning = False
            window.evaluate_js("scanComplete();")
    
    def get_results(self):
        return self.results
    
    def stop_scan(self):
        self.is_scanning = False

class Api:
    def __init__(self):
        self.scanner = TaskScanner()
    
    def start_scan(self):
        if self.scanner.is_scanning:
            return False
        if not webview.windows:
            return False
        window = webview.windows[0]
        thread = threading.Thread(target=self.scanner.scan_tasks, args=(window,))
        thread.daemon = True
        thread.start()
        return True
    
    def stop_scan(self):
        self.scanner.stop_scan()
        return True
    
    def get_results(self):
        return self.scanner.get_results()
    
    def clear_results(self):
        self.scanner.results = []
        return True
    
    def window_minimize(self):
        if webview.windows:
            webview.windows[0].minimize()
        return True
    
    def window_maximize(self):
        if webview.windows:
            window = webview.windows[0]
            window.toggle_fullscreen()
        return True
    
    def window_close(self):
        if webview.windows:
            webview.windows[0].destroy()
        return True
    
    def window_move(self, x, y):
        if webview.windows:
            webview.windows[0].move(x, y)
        return True

def get_web_files_path():
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    web_path = os.path.join(base_path, 'web')
    return web_path

def create_fallback_html():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>TasksParser - Error</title>
    <style>
        body { background: #0f172a; color: white; font-family: Arial; margin: 0; padding: 20px; }
        .error { color: #ef4444; background: rgba(239, 68, 68, 0.1); padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>TasksParser - Task Analysis</h1>
    <div class="error">
        Error: Web files not found. Please ensure the 'web' folder with UI.html exists.
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    if getattr(sys, 'frozen', False) and sys.platform == 'win32':
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    
    api = Api()
    web_path = get_web_files_path()
    ui_html_path = os.path.join(web_path, 'UI.html')
    
    if os.path.exists(ui_html_path):
        try:
            if getattr(sys, 'frozen', False):
                url = f'file:///{ui_html_path}'.replace('\\', '/')
            else:
                url = ui_html_path
            
            window = webview.create_window(
                'TasksParser - Task Analysis',
                url=url,
                width=1600,
                height=900,
                resizable=True,
                frameless=True,
                easy_drag=False,
                min_size=(1200, 700),
                js_api=api
            )
        except Exception as e:
            window = webview.create_window(
                'TasksParser - Task Analysis',
                html=create_fallback_html(),
                width=1600,
                height=900,
                resizable=True,
                frameless=True,
                easy_drag=False,
                min_size=(1200, 700),
                js_api=api
            )
    else:
        window = webview.create_window(
            'TasksParser - Task Analysis',
            html=create_fallback_html(),
            width=1600,
            height=900,
            resizable=True,
            frameless=True,
            easy_drag=False,
            min_size=(1200, 700),
            js_api=api
        )
    
    webview.start(debug=False)