# Destra

Destra is a core feature of Hive, the flagship product of ReaQta. Destra, 
as Detection Strategy, is a Lua (extended) engine that allows security operators to write 
custom detections rules.

These detections rules are executed directly on the endpoint. A detection rule 'binds'
to one or multiple events. When those events are observed, they are given as input to the 
Lua script. The Lua code is called for every bound event.

In this document you will find the details of the data structures you can access with
Destras and the helper functions you can call to perform specific actions (e.g., create
alert in the dashboard directly from your Destra code).

This documentation is a work-in-progress and it should be sufficient to get you started
to write your first Destra and to understand the majority of Destras available in your
deployments.

Currently, Destra cannot be tested offline before pushing them to the agents, therefore
it is advised to test it in a dedicated environment. We consider Destra a feature for
advanced users.

Please for more clarity on the Lua terms we refer the reader to the official
[Lua Documentation](https://www.lua.org/).

Highlighted Sections:

- [Events Table](#event-table)
- [Process Table](#process-table)
- [Program Table](#program-table)
- [Functions](#functions)

## Current Engine Version: 4

Supported Agents version:

- Windows agent >=`3.5.0`

## Engine Version

Engine version is a variable injected in the Destra code used to check if the detection 
strategy supports a specific feature.

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
__engine_version | number | engine version identifier

Example:

```lua
if __engine_version < 4 then return end
```

## Event Table

*Lua Table* containing information about the event currently injected in the script.
*This is the main input data structure of a Destra.*

`event` table variable is accessible at every call of the Destra script.

Content of the `event` table, accessible using *dot syntax*

The most relevant information in an Event table are contained in the `process`, 
`parentProcess` and `data` fields.

Example:

```lua
event.eventType == 2
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----
eventType | number | type of the event
eventId | number | unique identifier of the event
happenedAt | number | timestamp of the event
process | [Process Table](#process-table) | a table representing the information of the process triggering the event.
parentProcess | [Process Table](#process-table) | a table representing the parent process information of the process triggering the event.
data | [Data Table](#data-tables) | a table representing the specific payload of the event depending on the `eventType`

## Process Table

*Lua Table* representing information for the process associated with an event.

Content of the `process` table, accessible using *dot syntax*.

Example:

```lua
event.process.pid == 1234
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
pid | number | process identifier
startTime | number | process start time in milliseconds
ppid | number | parent process identifier
pstartTime | number | parent process start time in milliseconds
privilegeLevel | string | string representing privilege of the process | **Windows Only**. Refer to [Process privilege level field](#process-privilege-level-field) for list of the possible values
user | string | user of the process |
cmdLine | string | |
program | [Program Table](#program-table) | |
loginId | string | login Id associated with the Session of the current User | **Windows Only**
loginIdn | number | login Id associated with the Session of the current User | **Windows Only**

## Program Table

*Lua Table* representing information for the program associated with an event.

Content of the `program` table, accessible using *dot syntax*.

Example:

```lua
event.process.program.filename == "explorer.exe"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
path | string | program path |
sha256 | string | hash 256 of program path |
sha1 | string | hash sha1 of program path |
md5 | string | hash md5 of program path |
filename | string | original Filename of program | **Windows Only**, on other OSes the filename is always the same as `fsName`
fsName | string | last part of the path | for **Windows** include the extension as well
certInfo | [Certificate Info Table](#certificate-info-table) | Table representing Certificate information | **Windows Only**

## Certificate Info Table

### WINDOWS ONLY

*Lua Table* representing information for the certificate associated with a program.

Content of the `certInfo` table, accessible using *dot syntax*.

Example:

```lua
event.process.program.certInfo.signer:lower():find("ReaQta")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
found | boolen | if the certificate is present or not |
signer | string | signer of the certificate |
issuer | string | issuer of the certificate |
trusted | boolen | if the Windows operating system was able to verify the Certificate |
expired | boolen | represent if the Certificate is expired |

## Process privilege level field

WIP

## Data Tables

The `event.data` table is associated with the `event` table and depends from the `event.eventType`.

Every `event.eventType` has different `event.data` table.

Event | eventType   | Table |
----------- | ----------- | ----- |
Process Created | 2 | [Process Create Data](#data-process-created)
Process Terminated | 3 | [No Data](#data-empty)
Cross-process Operation | 4 | [Cross-process Operation Data](#data-cross-process-operation)
File Deleted | 7 | [File Operation Data](#data-file-operation)
Network Connection Established | 8 | [Network Connection Established Data](#data-network-connection-established)
Registry Persistence | 9 | [Registry Operation Data](#data-registry-operation)
File Written | 12 | [File Operation Data](#data-file-operation)
Executable Dropped | 13 | [File Operation Data](#data-file-operation)
Executable Duplicated | 14 | [File Operation Data](#data-file-operation)
Keylog | 15 | [No Data](#data-empty)
Screenshot | 16 | [No Data](#data-empty)
Privilege Escalation | 17 | [No Data](#data-empty)
File System Persistence | 18 | [File Operation Data](#data-file-operation)
Process Impersontation | 20 | [Process Impersonation Data](#data-cross-process-operation)
File Read | 21 | [File Operation Data](#data-file-operation)
Forged Digital Signature | 22 | [No Data](#data-empty)
Harvested Credentials | 23 | [No Data](#data-empty)
Dll Hijacking | 23 | [Dll Hijacking Data](#data-dll-hijacking)
Suspicious Script | 27 | [Suspicious Script Data](#data-suspicious-script)
Behavioural Anomaly | 31 | [No Data](#data-empty)
RAT Behaviour | 35 | [No Data](#data-empty)
WMI Activity | 36 | [WMI Activity Data](#data-wmi-activity)
ETW WinINet | 37 | [ETW WinINet Data](#data-etw-wininet)
ETW DNS | 38 | [ETW DNS Data](#data-etw-dns)
Account logged On | 39 | [Account Logged On Data](#data-account-logged-on)
Account logged On Failed | 40 | [Account Logged On Failed Data](#data-account-logged-on-failed)
Login Special Priv Assigned| 56 | [Login Special Priv Assigned Data](#data-login-special-priv-assigned)
Module Loaded | 57 | [Module Loaded](#data-module-loaded)
WMI Process Created | 58 | [Wmi Process Created](#data-child-process-created)
Custom Event | 60 | [Custom Event](#data-custom-event)
Custom Event No Process | 61 | [Custom Event No Process](#data-custom-event)
Macro Enabled Document | 62 | [Macro Enabled Document](#data-macro-enabled-document)
In Memory Executable | 63 | [In Memory Executable](#data-in-memory-executable)
Process Killed | 64 | [Process Killed](#data-process-killed)
Mitre ATTA&CK | 65 | [Mitre ATTA&CK](#data-mitre-attack)
WMI Event Filter | 66 | [WMI Event Filter](#data-wmi-event-filter)
WMI Event Consumer | 67 | [WMI Event Consumer](#data-wmi-event-consumer)
WMI Filer to Consumer | 68 | [WMI Filter to Consumer](#data-wmi-filter-to-consumer)
COM Object Hijacked | 70 | [COM Object Hijacked](#data-com-object-hijacked)
User Account Created | 71 | [User Account Created](#data-user-account-created)
User Account Deleted | 72 | [User Account Deleted](#data-user-account-deleted)
Powershell Script Block Logged | 74 | [Powershell Script Block Logged](#data-powershell-script-block-logged)
ETW Security Audit | 75 | [ETW Security Audit](#data-etw-security-audit)
Scheduled Task Created | 81 | [Scheduled Task Created](#data-scheduled-task)
Scheduled Task Deleted | 82 | [Scheduled Task Deleted](#data-scheduled-task)
Scheduled Task Updated | 83 | [Scheduled Task Updated](#data-scheduled-task)
Scheduled Task Executed | 84 | [Scheduled Task Executed](#data-scheduled-task)
Service Creted | 85 | [Service Created](#data-windows-service-operation)
Service Deleted | 86 | [Service Deleted](#data-windows-service-operation)
Service Started | 87 | [Service Started](#data-windows-service-operation)
Service Stopped | 88 | [Service Stopped](#data-windows-service-operation)
AMSI Anti-malware Scan Interface | 89 | [AMSI](#data-amsi)
Mitre ATTA&CK No Process | 90 | [Mitre ATTA&CK No Process](#data-mitre-attack)

### Data Empty

No `data` table associated with this `event.eventType`.

### Data Process Created

*Lua Table* representing data associated to `Process Created` `event`.

Example:

```lua
event.data.cmdLine:lower():find("aHR0cHM6Ly90d2l0dGVyLmNvbS9nTjNtZXMxcw")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
cmdLine | string | |

### Data Cross-process Operation

*Lua Table* representing data associated to `Cross-process Operation`, `Process Impersonation` `event`.
The event data is related to the process targeted by these events.

Example:

```lua
event.data.targetProcess.program.filename:lower():find("aHR0cHM6Ly90d2l0dGVyLmNvbS9nTjNtZXMxcw")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
targetProcess | [Process Table](#process-table) | |

### Data File Operation

*Lua Table* representing data associated to `File Delete`, `File Written`, `Executable Dropped`, `Executable Duplicated`, `File Read`  `event`.

Example:

```lua
event.data.file:find("temp")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
file | string | path of the file |
sha256 | string | hash sha256 of the file |

### Data Network Connection Established

*Lua Table* representing data associated to `Network Connection Establised` `event`.

Example:

```lua
event.data.localAddr:find("192.168.71.132")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
localAddr | string | |
localPort | number | |
remoteAddr | string | |
remotePort | number | |
outbound | boolean | direction of the connection |

### Data Registry Operation

*Lua Table* representing data associated to `Registry Persistence` `event`.

Example:

```lua
event.data.rootObject:find("run")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
rootObject | string | |
name | string | |
data | string | |

### Data Dll Hijacking

*Lua Table* representing data associated to `Dll Hijacking` `event`.

Example:

```lua
event.data.path:find("run")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
path | string | |
sha256 | string | |
sha1 | string | |
md5 | string | |
size | number | |
certInfo | [Certificate Info Table](#certificate-info-table) | Table representing Certificate information | **Windows Only**
arch | string | |

### Data Suspicious Script

*Lua Table* representing data associated to `Suspicious Script` `event`.

Example:

```lua
event.data.path:find("run")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
path | string | |
sha256 | string | |
sha1 | string | |
md5 | string | |
size | number | |

### Data WMI Activity

*Lua Table* representing data associated to `WMI Activity` `event`.

Example:

```lua
event.data.operation:find("win32 process call create")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
operation | string | |
namespaceName | string | |
etwEventId | number | |
hostPid | number | |
activityId | number | | please refer to [Wmi Activity Id](#data-wmi-activity-id)
clientPid | number | |
clientMachine | string | |
clientMachineFqn | string | |
isLocal | boolean | |
user | string | |

#### Data WMI Activity Id

Mapping number with the specific activity.

Number   | Activity | Meaning | Remarks
----    |------ | ---- | ----------
0 | Undefined | |
1 | Win32_process_create | |
2 | ExecQuery | |
3 | CreateInstanceEnum | |
4 | ExecMethod | |

### Data ETW WinINet

*Lua Table* representing data associated to `ETW WinINet` `event`.

Example:

```lua
event.data.url:find("malicious.com")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
url | string | |
requestHeaders | string | |
responseHeaders | string | |

### Data ETW DNS

*Lua Table* representing data associated to `ETW DNS` `event`.

Example:

```lua
event.data.queryName:find("malicious.com")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
queryName | string | |
queryResults | string | |

### Data Account Logged On

*Lua Table* representing data associated to `Account Logged On` `event`.

Example:

```lua
event.data.etwLogonType == 10 and event.data.etwTargetLogonId == "0x1234"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
etwEventVersion | number | |
etwTimeCreated | string | |
etwSubjectUserName | string | |
etwSubjectDomainName | string | |
etwSubjectLogonId | string | |
etwTargetUserSid | string | |
etwTargetUserName | string | |
etwTargetDomainName | string | |
etwTargetLogonId | string | |
etwLogonType | number | |
etwAuthenticationPackageName | string | |
etwWorkstationName | string | |
etwLogonProcessName | string | |

### Data Account Logged On Failed

*Lua Table* representing data associated to `Account Logged On Failed` `event`.

Example:

```lua
event.data.etwLogonType == 10 and event.data.etwIpAddress:find("192.")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
etwEventVersion | number | |
etwTimeCreated | string | |
etwSubjectUserName | string | |
etwSubjectDomainName | string | |
etwSubjectLogonId | string | |
etwTargetUserSid | string | |
etwTargetUserName | string | |
etwTargetDomainName | string | |
etwLogonType | number | |
etwAuthenticationPackageName | string | |
etwStatus | string | |
etwIpAddress | string | |
etwLogonProcessName | string | |
etwWorkstationName | string | |

### Data Login Special Priv Assigned

*Lua Table* representing data associated to `Login Special Priv Assigned` `event`.

Example:

```lua
event.data.etwSubjectLogonId == "0x1234"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
etwEventVersion | number | |
etwTimeCreated | string | |
etwSubjectUserName | string | |
etwSubjectLogonId | string | |
etwSubjectUserSid | string | |
etwSubjectLogonId | string | |
etwPrivilegeList | string | |

### Data Module Loaded

*Lua Table* representing data associated to `Module Loaded` `event`.

Example:

```lua
event.data.path:find("run")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
path | string | |
sha256 | string | |
sha1 | string | |
md5 | string | |
filename | string | |
fsName | string | |
size | number | |
description | string | |
arch | string | |
creationTime | string | |
accessTime | string | |
lastWriteTime | string | |
fileType | number | | please refer to [File Type](#data-file-type)
certInfo | [Certificate Info Table](#certificate-info-table) | Table representing Certificate information | **Windows Only**

#### Data File Type

Mapping number with the specific activity.

Number   | Type | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | Exe | |
2 | Dll | |

### Data Child Process

*Lua Table* representing data associated to `WMI Process Created` `event`.

Example:

```lua
event.data.childProcess.program.filename:find("malware")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
childProcess | [Process Table](#process-table) | |

### Data Custom Event

*Lua Table* representing data associated to `Custom Event`, `Custom Event No Process` `event`.

Example:

```lua
event.data.type == "my_own_type"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
type | string | |
name | string | |
description | string | |
relevance | number | |
tags | table | Array of strings representing tags associated with an event |
custom_data | table | Map key (string) <-> value (string) |

### Data Macro Enabled Document

*Lua Table* representing data associated to `Macro Enabled Document` `event`.

Example:

```lua
event.data.path:find("temp")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
path | string | |
sha256 | string | |
sha1 | string | |
md5 | string | |
size | number | |
creationTime | string | |
accessTime | string | |
lastWriteTime | string | |

### Data In Memory Executable

*Lua Table* representing data associated to `In Memory Executable` `event`.

Example:

```lua
event.data.allocatorProc.program.filename == "malware"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
peType | number | | please refer to [PE Type](#data-pe-type)
arch | string | |
allocationType | number | |
memProtection | number | |
baseAddress | number | |
allocatorProc | [Process Table](#process-table) | process that requested the allocation |
size | number | |

#### Data PE Type

Mapping number with the specific activity.

Number   | Type | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | Exe | |
2 | Dll | |

### Data Process Killed

*Lua Table* representing data associated to `Process Killed` `event`.

Example:

```lua
event.data.targetProcess.program.filename == "explorer.exe"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
returnCode | number | |
targetProcessId | number | |
targetProcess | [Process Table](#process-table) | Process that has been killed |

### Data Mitre Attack

*Lua Table* representing data associated to `Mitre ATT&CK` `event`.

Example:

```lua
event.data.technique == "T1086"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
technique | string | |
relevance | number | |
tactics | table | array of number  | please refer to [Mitre ATT&CK Tactics](#data-mitre-attack-tactics)

#### Data Mitre Attack Tactics

Mapping number with the specific tactic.

Number   | Tactic | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | InitialAccess | |
2 | Execution | |
3 | Persistence | |
4 | PrivilegeEscalation | |
5 | DefenseEvasion | |
6 | CredentialAccess | |
7 | Discovery | |
8 | LateralMovement | |
9 | Collection | |
10 | CommandAndControl | |
11 | Exfiltration | |
12 | Impact | |

### Data WMI Event Filter

*Lua Table* representing data associated to `WMI Event Filter` `event`.

Example:

```lua
event.data.query:find("select")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
operationType | number | | please refer to [WMI Instance Operation Type](#data-wmi-instance-operation-type)
eventNamespace | string | |
query | string | |
queryLanguage | string | |
filterName | string | |

#### Data WMI Instance Operation Type

Mapping number with the specific activity.

Number   | Type | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | Create | |
2 | Delete | |
3 | Modify | |

### Data WMI Event Consumer

*Lua Table* representing data associated to `WMI Event Consumer` `event`.

Example:

```lua
event.data.query:find("select")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
operationType | number | | please refer to [WMI Instance Operation Type](#data-wmi-instance-operation-type)
consumerType | number | | please refer to [WMI Event Consumer Type](#data-wmi-event-consumer-type)
consumerName | string | |
cmdLineConsumerData | [WMI CommandLine Consumer Table](#wmi-commandline-consumer-table) | Table representing info about consumer|
activeScriptConsumerData | [WMI ActiveScript Consumer Table](#wmi-activescript-consumer-table) | Table representing info about consumer|

#### Data WMI Event Consumer Type

Mapping number with the specific activity.

Number   | Type | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | ActiveScriptEventConsumer | |
2 | LogFileEventConsumer | |
3 | NTEventLogEventConsumer | |
4 | SMTPEventConsumer | |
5 | CommandLineEventConsumer | |

#### WMI CommandLine Consumer Table

*Lua Table* representing `CommandLine Consumer` in a `WMI Event Consumer` `event`.

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
commandLineTemplate | string | |
commandLineTemplate | string | |
executablePath | string | |
showWindowCommand | number | |
runInteractively | number | |
workingDirectory | string | |

#### WMI ActiveScript Consumer Table

*Lua Table* representing `ActiveScript Consumer` in a `WMI Event Consumer` `event`.

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
scriptingEngine | string | |
scriptText | string | |
scriptFileName | string | |
killTimeout | number | |

### Data WMI Filter To Consumer

*Lua Table* representing data associated to `WMI Filter To Consumer` `event`.

Example:

```lua
event.data.query:find("select")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
operationType | number | | please refer to [WMI Instance Operation Type](#data-wmi-instance-operation-type)
consumerType | number | | please refer to [WMI Event Consumer Type](#data-wmi-event-consumer-type)
eventNamespace | string | |
query | string | |
queryLanguage | string | |
filterName | string | |
consumerName | string | |
cmdLineConsumerData | [WMI CommandLine Consumer Table](#wmi-commandline-consumer-table) | Table representing info about consumer|
activeScriptConsumerData | [WMI ActiveScript Consumer Table](#wmi-activescript-consumer-table) | Table representing info about consumer|

### Data COM Object Hijacked

*Lua Table* representing data associated to `COM Object Hijacked` `event`.

Example:

```lua
event.data.rootObject:find("run")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
rootObject | string | |
name | string | |
data | string | |
valueType | number | |
hijackingType | number | | please refer to [COM Object Hijacking Type](#data-com-object-hijacking-type)

#### Data COM Object Hijacking Type

Mapping number with the specific activity.

Number   | Type | Meaning | Remarks
----    |------ | ---- | ----------
0 | Unknown | |
1 | RootObject | |
2 | Value | |

### Data User Account Created

*Lua Table* representing data associated to `User Account Created` `event`.

Example:

```lua
event.data.etwTargetUserName:find("malicious")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
etwEventVersion | number | |
etwTimeCreated | string | |
etwSubjectUserName | string | |
etwSubjectUserSid | string | |
etwSubjectDomainName | string | |
etwSubjectLogonId | string | |
etwTargetUserSid | string | |
etwTargetUserName | string | |
etwTargetDomainName | string | |
etwPrivilegeList | string | |
etwPrimaryGroupId | string | |

### Data User Account Deleted

*Lua Table* representing data associated to `User Account Deleted` `event`.

Example:

```lua
event.data.etwTargetUserName:find("malicious")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
etwEventVersion | number | |
etwTimeCreated | string | |
etwSubjectUserName | string | |
etwSubjectUserSid | string | |
etwSubjectDomainName | string | |
etwSubjectLogonId | string | |
etwTargetUserSid | string | |
etwTargetUserName | string | |
etwTargetDomainName | string | |
etwPrivilegeList | string | |

### Data Powershell Script Block Logged

*Lua Table* representing data associated to `Powershell Script Block Logged` `event`.

Example:

```lua
event.data.scriptBlockText:find("kernel32")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
tid | number | |
scriptBlockText | string | |
scriptBlockSize | number | |
path | string | |
scriptBlockId | string | |
entropy | number | |

### Data ETW Security Audit

*Lua Table* representing data associated to `ETW Security Audit` `event`.

Example:

```lua
event.data.etwEventId ~= 4732
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
etwEventVersion | number | |
etwTimeCreated | string | |
etwEventId | number | |
etwTask | number | |
etwEventDescription | string | |

### Data Scheduled Task

*Lua Table* representing data associated to `Scheduled Task Created`, `Scheduled Task Deleted`, `Scheduled Task Updated`, `Scheduled Task Executed` `event`.

Example:

```lua
event.data.actionName == "start malware"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
hostPid | number | |
wmiHostPid | number | |
etwEventId | number | |
enginePid | number | |
etwActivityId | string | |
taskName | string | |
path | string | |
actionName | string | |
engineProcess | [Process Table](#process-table) | Process created from the scheduled task |

### Data Windows Service Operation

*Lua Table* representing data associated to `Service Created`, `Service Deleted`, `Service Started`, `Service Stopped` `event`.

Example:

```lua
event.data.serviceName == "malicious"
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
hostPid | number | |
wmiHostPid | number | |
servicePid | number | |
rootObject | string | |
serviceName | string | |
path | string | |
displayName | string | |
serviceProcess | [Process Table](#process-table) | Process created from the service request |

### Data AMSI

*Lua Table* representing data associated to `AMSI Anti-malware Scan Interface` `event`.

Example:

```lua
event.data.content:find("malicious")
```

Field   | Type | Meaning | Remarks
----    |------ | ---- | ----------
version | number | |
scanResult | number | |
appName | string | |
contentSize | number | |
originalSize | number | |
contentName | string | |
content | string | |

## Functions

The engine expose function to make it easy some tasks like:

- Create new event
- Checking type of event
- Create an alert

The following section is going to explain every function available and what is it used for.

Function| Type | Meaning | Remarks
---- | ---- | ---- | ----------
is_* | [is functions](#is-functions) | set of function used to assert if the analyzed event is the expected type | Please refer to [is functions](#is-functions)  for more details
create_alert | [Create Alert Function](#create-alert) | create a Hive Alert from an event
create_event | [Create Custom Event Function](#create-event) | create a custom event | [Custom Event](#data-custom-event) and [Custom Event No Process](#data-custom-event) data
mitre_event | [Mitre Event Function](#mitre-event) | create a mitre event

### Is Functions

`Is_*` *lua functions* are special functions that verify if an event is of the expected type.
You can access all the available `is_*` *lua functions* from the `event` table using the `.` operator.

The *lua function* signature is the same for all the `is_*` functions.

Function Signature:

```c++
bool is_function()
```

Available `is` functions:

Function | Event | eventType
----------- | ----------- | ----- |
is_process_created | Process Created | 2
is_process_terminated | Process Terminated | 3
is_cross_proc | Cross-process Operation | 4
is_file_delete | File Deleted | 7
is_net_established | Network Connection Established | 8
is_reg_persistence | Registry Persistence | 9
is_exec_dropped | Executable Dropped | 13
is_exec_duplicated | Executable Duplicated | 14
is_keylogging | Keylog | 15
is_screenshot | Screenshot | 16
is_privesc | Privilege Escalation | 17
is_file_persistence | File System Persistence | 18
is_proc_impersonation | Process Impersontation | 20
is_signature_forged | Forged Digital Signature | 22
is_cred_harvested | Harvested Credentials | 23
is_susp_script | Suspicious Script | 27
is_anomalous_behaviour | Behavioural Anomaly | 31
is_rat | RAT Behaviour | 35
is_wmi_activity | WMI Activity | 36
is_wininet | ETW WinINet | 37
is_dns_actvity | ETW DNS | 38
is_account_logged_on | Account logged On | 39
is_account_log_on_failed | Account logged On Failed | 40
is_special_priv_assigned | Login Special Priv Assigned| 56
is_module_loaded | Module Loaded | 57
is_wmi_process_created | WMI Process Created | 58
is_custom_event | Custom Event | 60
is_custom_event | Custom Event No Process | 61
is_macro_enabled | Macro Enabled Document | 62
is_inmem_exec | In Memory Executable | 63
is_process_killed | Process Killed | 64
is_technique_detected | Mitre ATTA&CK | 65
is_wmi_filter | WMI Event Filter | 66
is_wmi_consumer | WMI Event Consumer | 67
is_wmi_filtertoconsumer | WMI Filer to Consumer | 68
is_wmi_persistence | WMI Filer to Consumer | 68
is_com_hijacking | COM Object Hijacked | 70
is_account_user_created | User Account Created | 71
is_account_user_deleted | User Account Deleted | 72
is_powershell_script_logged | Powershell Script Block Logged | 74
is_etw_security_auditing | ETW Security Audit | 75
is_task_created | Scheduled Task Created | 81
is_task_deleted | Scheduled Task Deleted | 82
is_task_updated | Scheduled Task Updated | 83
is_task_executed | Scheduled Task Executed | 84
is_service_created | Service Creted | 85
is_service_deleted | Service Deleted | 86
is_service_started | Service Started | 87
is_service_stopped | Service Stopped | 88
is_amsi | AMSI Anti-malware Scan Interface | 89
is_technique_detected_no_process | Mitre ATTA&CK No Process | 90

Example:

```lua
-- this can be used when you bind to multiple event types from the same Destra
-- in this case we bound the Destra to:
--  ProcessCreated
--  ExecutableDropped
if event.is_process_created() then
    logger("I'm a process created event")
elseif event.is_exec_dropped() then
    logger("I'm an executable dropped event")
else then
    logger("I SHOULD NEVER BE HERE!")
end
```

### Create Alert

*Lua function* used to create a new Hive Alert.

Function Signature:

```c++
bool create_alert(array Events, string Title, number Impact, string Notes, array string Tags)
```

Parameter Details:

Parameter | Type | Meaning | Remarks
---- | ---- | ---- | ----------
Events | array of [Events](#event-table) | Trigger events of the Hive Alert
Title | string | Title of the alert that is going to be generate on Hive
Impact | number | Impact that will be part of the Hive Alert
Notes | string | Notes is going to fill the Notes field in the Hive Alert
Tags | array of string | Tags part of the Hive Alert

Example:

```lua
local events = {event}
local title = "Hive alert Title"
local impact = 100
local notes = "this is a note in the hive alert"
local tags = {"tests", "hive", "custom", "alert"}
local res = create_alert(events, title, impact, notes, tags)
```

### Create Event

*Lua function* used to create a [Custom Event](#data-custom-event) or [Custom Event No Process](#data-custom-event) from a bound event.
Note that not all event fields will be searchable with the threat hunt functionalities.
The fields will be present in the data object, but not all can be searched from the User
Interface.

Function Signature:

```c++
bool create_event(table Event, number Version, string Type, string Name, string Description, number relevance, array string Tags, table Data)
```

Parameter Details:

Parameter | Type | Meaning | Remarks
---- | ---- | ---- | ----------
Event | [Event](#event-table) | Base event from where the Custom event will be derived | If the events doesn't have a process the generated event will be *Custom Event No Process*
Version | number | event version
Type | string | type of the events | This field is searchable from the threat hunt functionalities.
Name | string | name of the event | This field is searchable from the threat hunt functionalities.
Description | string | description of the event that will be visible in the Event list in Hive Dashboard
Relevance | number | relevance of the event representing how malicious is the new event generated
Tags | array of string | Tags part of the Custom event generated
Data | table | Map key (string) <-> value (string) | will popolate the `custom_data`, please refer to [Custom Event](#data-custom-event) or [Custom Event No Process](#data-custom-event). This field is *not searchable* in the threat hunt functionalities.

Example:

```lua
local type = "type"
local name = "name"
local description = "description"
local relevance = 95
local version = 1
local tags = {"tag1", "tag2"}
local data = {key="value", key2="value2"}
local res = create_event(event, version, type, name, description, relevance, tags, data)
```

### Mitre Event

*Lua function* used to create a [Mitre ATTA&CK event](#data-mitre-attack) from a bound event.
Note that not all event fields will be searchable with the threat hunt functionalities.
The fields will be present in the data object, but not all can be searched from the User
Interface.

Function Signature:

```c++
bool mitre_event(table Event, string Technique, number Relevance, array Tactics, table Data)
```

Parameter Details:

Parameter | Type | Meaning | Remarks
---- | ---- | ---- | ----------
Event | [Event](#event-table) | Base event from where the Mitre Event will be derived
Technique | string | | This field is searchable with the threat hunt functionalities.
Relevance | number | | This field is searchable with the threat hunt functionalities.
Tactics | table | array of number  | please refer to [Mitre ATT&CK Tactics](#data-mitre-attack-tactics)
Data | table | Map key (string) <-> value (string) | This field is *not searchable* with the threat hunt functionalities.

Example:

```lua
local technique = "T1190"
local relevance = 95
local tactics = {1, 2} -- mapped to InitialAccess, Execution
local data = {key="value", key2="value2"}
local res = mitre_event(event, technique, relevance, tactics, data)
```
