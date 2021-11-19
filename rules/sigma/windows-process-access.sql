--********************************************************************--
-- Author:         xiao.xing
-- Created Time:   2021-11-02 15:38:39
-- Description:    sysmon检测规则
--********************************************************************--


CREATE TEMPORARY TABLE `sysmon_table` (
    computer_name STRING,
    event_id BIGINT,
    host STRING,
    event_data ROW< 
        CallTrace STRING,
        GrantedAccess STRING,
        SourceImage String,
        TargetImage String,
        Image STRING, 
        ParentImage STRING,
        CommandLine STRING, 
        ParentCommandLine STRING, 
        UtcTime STRING 
    >,
    uuid STRING,
  `timestamp` TIMESTAMP(3) METADATA,
  WATERMARK FOR `timestamp` AS `timestamp` - INTERVAL '5' SECOND
) WITH (
  'connector' = 'kafka',
  'topic' = '${kafka_source_topic}',
  'properties.group.id' = '${kafka_group_id}',
  'properties.bootstrap.servers' = '${kafka_brokers}',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.timestamp-format.standard' = 'ISO-8601',
  'json.ignore-parse-errors' = 'true'
);


CREATE TEMPORARY TABLE `alert_table` (
    computer_name STRING,
    host STRING,
    event ROW<
        kind STRING,
        module STRING,
        origin_ids ARRAY<STRING>,
        `count` BIGINT,
        `start` TIMESTAMP,
        `end` TIMESTAMP,
        `time` TIMESTAMP
    >,
    threat ROW<
        tactic ARRAY<STRING>,
        technique ARRAY<STRING>,
        subtechnique ARRAY<STRING>
    >,
    rule ROW <
        name STRING,
        author STRING,
        category STRING,
        severity INTEGER,
        description STRING,
        reference ARRAY<STRING>,
        version STRING,
        source STRING
    >
) WITH (
  'connector' = 'kafka',
  'topic' = '${kafka_sink_topic}',
  'properties.bootstrap.servers' = '${kafka_brokers}',
  'format' = 'json'
);

BEGIN STATEMENT SET;


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.defense_evasion', 'attack.privilege_escalation'], ARRAY['attack.t1055'], ARRAY['']) AS threat,
    ROW('Malware Shellcode in Verclsid Target Process',
        'John Lambert (tech), Florian Roth (rule)',
        'sysmon',
        7,
        'Detects a process access to verclsid.exe that injects shellcode from a Microsoft Office application / VBA macro',
        ARRAY['https://twitter.com/JohnLaTwC/status/837743453039534080'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND ((`event_data`.`TargetImage` LIKE '%\verclsid.exe') AND (`event_data`.`GrantedAccess` = '0x1FFFFF') AND ((`event_data`.`CallTrace` LIKE '%|UNKNOWN(%' AND `event_data`.`CallTrace` LIKE '%VBE7.DLL%')) OR ((`event_data`.`SourceImage` LIKE '%\Microsoft Office\%') AND (`event_data`.`CallTrace` LIKE '%|UNKNOWN%')))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.privilege_escalation', 'attack.defense_evasion'], ARRAY['t1055', 't1055', 'attack.t1055'], ARRAY['attack.t1055.001', 'attack.t1055.002']) AS threat,
    ROW('Suspicious In-Memory Module Execution',
        'Perez Diego (@darkquassar), oscd.community, Jonhnathan Ribeiro',
        'sysmon',
        9,
        'Detects the access to processes by other suspicious processes which have reflectively loaded libraries in their memory space. An example is SilentTrinity C2 behaviour. Generally speaking, when Sysmon EventID 10 cannot reference a stack call to a dll loaded from disk (the standard way), it will display "UNKNOWN" as the module name. Usually this means the stack call points to a module that was reflectively loaded in memory. Adding to this, it is not common to see such few calls in the stack (ntdll.dll --> kernelbase.dll --> unknown) which essentially means that most of the functions required by the process to execute certain routines are already present in memory, not requiring any calls to external libraries. The latter should also be considered suspicious.',
        ARRAY['https://azure.microsoft.com/en-ca/blog/detecting-in-memory-attacks-with-sysmon-and-azure-security-center/'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND ((`event_data`.`CallTrace` LIKE '%C:\WINDOWS\SYSTEM32\ntdll.dll+%' AND `event_data`.`CallTrace` LIKE '%|C:\WINDOWS\System32\KERNELBASE.dll+%' AND `event_data`.`CallTrace` LIKE '%|UNKNOWN(%' AND `event_data`.`CallTrace` LIKE '%)%') OR (`event_data`.`CallTrace` LIKE '%UNKNOWN(%' AND `event_data`.`CallTrace` LIKE '%)|UNKNOWN(%') AND (`event_data`.`CallTrace` LIKE '%)') OR (`event_data`.`CallTrace` LIKE '%UNKNOWN%') AND (`event_data`.`GrantedAccess` IN ('0x1F0FFF', '0x1F1FFF', '0x143A', '0x1410', '0x1010', '0x1F2FFF', '0x1F3FFF', '0x1FFFFF')) AND NOT ((`event_data`.`SourceImage` LIKE '%\Windows\System32\sdiagnhost.exe')))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access'], ARRAY['t1003'], ARRAY['attack.t1003.001']) AS threat,
    ROW('Credential Dumping by LaZagne',
        'Bhabesh Raj, Jonhnathan Ribeiro',
        'sysmon',
        9,
        'Detects LSASS process access by LaZagne for credential dumping.',
        ARRAY['https://twitter.com/bh4b3sh/status/1303674603819081728'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\lsass.exe') AND (`event_data`.`CallTrace` LIKE '%C:\\Windows\\SYSTEM32\\ntdll.dll+%' AND `event_data`.`CallTrace` LIKE '%|C:\\Windows\\System32\\KERNELBASE.dll+%' AND `event_data`.`CallTrace` LIKE '%_ctypes.pyd+%' AND `event_data`.`CallTrace` LIKE '%python27.dll+%') AND (`event_data`.`GrantedAccess` = '0x1FFFFF')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.defense_evasion'], ARRAY['t1562', 'attack.t1089'], ARRAY['attack.t1562.002']) AS threat,
    ROW('Suspect Svchost Memory Asccess',
        'Tim Burrell',
        'sysmon',
        7,
        'Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.',
        ARRAY['https://github.com/hlldz/Invoke-Phant0m', 'https://twitter.com/timbmsft/status/900724491076214784'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\WINDOWS\System32\svchost.exe') AND (`event_data`.`GrantedAccess` = '0x1F3FFF') AND (`event_data`.`CallTrace` LIKE '%UNKNOWN%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY[''], ARRAY['attack.t1548'], ARRAY['']) AS threat,
    ROW('SVCHOST Credential Dump',
        'Florent Labouyrie',
        'sysmon',
        9,
        'Detects when a process, such as mimikatz, accesses the memory of svchost to dump credentials',
        ARRAY[''],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND ((`event_data`.`TargetImage` LIKE '%\svchost.exe') AND (`event_data`.`GrantedAccess` = '0x143a') AND NOT ((`event_data`.`SourceImage` LIKE '%\services.exe') OR (`event_data`.`SourceImage` LIKE '%\msiexec.exe')))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.initial_access', 'attack.persistence', 'attack.privilege_escalation'], ARRAY['attack.t1190'], ARRAY['']) AS threat,
    ROW('Suspicious Shells Spawn by WinRM',
        'Andreas Hunkeler (@Karneades), Markus Neis',
        'sysmon',
        7,
        'Detects suspicious shell spawn from WinRM host process',
        ARRAY[''],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
         (`event_data`.`ParentImage` = '*\wsmprovhost.exe') AND (`event_data`.`Image` IN ('*\cmd.exe', '*\sh.exe', '*\bash.exe', '*\powershell.exe', '*\schtasks.exe', '*\certutil.exe', '*\whoami.exe', '*\bitsadmin.exe'))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.defense_evasion', 'attack.privilege_escalation'], ARRAY['t1548'], ARRAY['attack.t1548.002']) AS threat,
    ROW('UAC Bypass Using WOW64 Logger DLL Hijack',
        'Christian Burkard',
        'sysmon',
        7,
        'Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)',
        ARRAY['https://github.com/hfiref0x/UACME'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`SourceImage` LIKE '%:\Windows\SysWOW64\%') AND (`event_data`.`GrantedAccess` = '0x1fffff') AND (`event_data`.`CallTrace` LIKE 'UNKNOWN(0000000000000000)|UNKNOWN(0000000000000000)|%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.execution'], ARRAY['attack.t1106'], ARRAY['']) AS threat,
    ROW('Direct Syscall of NtOpenProcess',
        'Christian Burkard',
        'sysmon',
        9,
        'Detects the usage of the direct syscall of NtOpenProcess which might be done from a CobaltStrike BOF.',
        ARRAY['https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`CallTrace` LIKE 'UNKNOWN%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.execution', 'attack.defense_evasion'], ARRAY['attack.t1106', 't1562'], ARRAY['attack.t1562.001']) AS threat,
    ROW('CobaltStrike BOF Injection Pattern',
        'Christian Burkard',
        'sysmon',
        7,
        'Detects a typical pattern of a CobaltStrike BOF which inject into other processes',
        ARRAY['https://github.com/boku7/injectAmsiBypass', 'https://github.com/boku7/spawn'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`CallTrace` SIMILAR TO '^C:\\\\Windows\\\\SYSTEM32\\\\ntdll\\.dll\+[a-z0-9]{4,6}\|C:\\\\Windows\\\\System32\\\\KERNELBASE\\.dll\+[a-z0-9]{4,6}\|UNKNOWN\([A-Z0-9]{16}\)$') AND (`event_data`.`GrantedAccess` IN ('0x1028', '0x1fffff'))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access'], ARRAY['t1003', 'attack.t1003'], ARRAY['attack.t1003.001']) AS threat,
    ROW('LSASS Memory Dump',
        'Samir Bousseaden',
        'sysmon',
        7,
        'Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10',
        ARRAY['https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\lsass.exe') AND (`event_data`.`GrantedAccess` = '0x1fffff') AND (`event_data`.`CallTrace` IN ('dbghelp.dll', 'dbgcore.dll'))
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access'], ARRAY['t1003'], ARRAY['attack.t1003.001']) AS threat,
    ROW('Lsass Memory Dump via Comsvcs DLL',
        'Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)',
        'sysmon',
        9,
        'Detects adversaries leveraging the MiniDump export function from comsvcs.dll via rundll32 to perform a memory dump from lsass.',
        ARRAY['https://twitter.com/shantanukhande/status/1229348874298388484', 'https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\lsass.exe') AND (`event_data`.`SourceImage` = 'C:\Windows\System32\rundll32.exe') AND (`event_data`.`CallTrace` LIKE '%comsvcs.dll%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.execution'], ARRAY['t1204', 't1055'], ARRAY['attack.t1204.002', 'attack.t1055.003']) AS threat,
    ROW('LittleCorporal Generated Maldoc Injection',
        'Christian Burkard',
        'sysmon',
        7,
        'Detects the process injection of a LittleCorporal generated Maldoc.',
        ARRAY['https://github.com/connormcgarr/LittleCorporal'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`SourceImage` LIKE '%winword.exe') AND (`event_data`.`CallTrace` LIKE '%:\Windows\Microsoft.NET\Framework64\v2.%' AND `event_data`.`CallTrace` LIKE '%UNKNOWN%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.defense_evasion', 'attack.execution'], ARRAY['t1218', 'attack.t1191', 't1559', 'attack.t1175'], ARRAY['attack.t1218.003', 'attack.t1559.001']) AS threat,
    ROW('CMSTP Execution Process Access',
        'Nik Seetharaman',
        'sysmon',
        7,
        'Detects various indicators of Microsoft Connection Manager Profile Installer execution',
        ARRAY['https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`CallTrace` LIKE '%cmlua.dll%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.defense_evasion', 'attack.privilege_escalation'], ARRAY['t1548'], ARRAY['attack.t1548.002']) AS threat,
    ROW('Load Undocumented Autoelevated COM Interface',
        'oscd.community, Dmitry Uchakin',
        'sysmon',
        7,
        'COM interface (EditionUpgradeManager) that is not used by standard executables.',
        ARRAY['https://www.snip2code.com/Snippet/4397378/UAC-bypass-using-EditionUpgradeManager-C/', 'https://gist.github.com/hfiref0x/de9c83966623236f5ebf8d9ae2407611'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`CallTrace` LIKE '%editionupgrademanagerobj.dll%')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access'], ARRAY['t1003', 'attack.t1003'], ARRAY['attack.t1003.001']) AS threat,
    ROW('Credentials Dumping Tools Accessing LSASS Memory',
        'Florian Roth, Roberto Rodriguez, Dimitrios Slamaris, Mark Russinovich, Thomas Patzke, Teymur Kheirkhabarov, Sherif Eldeeb, James Dickenson, Aleksey Potapov, oscd.community (update)',
        'sysmon',
        7,
        'Detects process access LSASS memory which is typical for credentials dumping tools',
        ARRAY['https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow', 'https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html', 'https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment', 'http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND `event_data`.`TargetImage` LIKE '%\lsass.exe' AND `event_data`.`GrantedAccess` IN ('0x40', '0x1000', '0x1400', '0x100000', '0x1410', '0x1010', '0x1438', '0x143a', '0x1418', '0x1f0fff', '0x1f1fff', '0x1f2fff', '0x1f3fff')
        AND NOT (`event_data`.`SourceImage` LIKE '%\wmiprvse.exe' 
                OR `event_data`.`SourceImage` LIKE '%\taskmgr.exe'
                OR `event_data`.`SourceImage` LIKE '%\procexp64.exe'
                OR `event_data`.`SourceImage` LIKE '%\procexp.exe'
                OR `event_data`.`SourceImage` LIKE '%\lsm.exe' 
                OR `event_data`.`SourceImage` LIKE '%\MsMpEng.exe'
                OR `event_data`.`SourceImage` LIKE '%\csrss.exe'
                OR `event_data`.`SourceImage` LIKE '%\MsMpEng.exe'
                OR `event_data`.`SourceImage` LIKE '%\Microsoft.Exchange.Diagnostics.Service.exe'
                OR `event_data`.`SourceImage` LIKE '%\taskhostw.exe'
                OR `event_data`.`SourceImage` LIKE '%\svchost.exe'
                OR `event_data`.`SourceImage` LIKE '%\MicrosoftEdgeUpdate.exe'
                OR `event_data`.`SourceImage` LIKE '%\Microsoft.Tri.Gateway.Updater.exe'
                OR `event_data`.`SourceImage` = 'C:\Windows\system32\CompatTelRunner.exe'
                OR `event_data`.`SourceImage` LIKE '%\wininit.exe'
                OR `event_data`.`SourceImage` LIKE '%\vmtoolsd.exe')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access'], ARRAY['t1003'], ARRAY['attack.t1003.001']) AS threat,
    ROW('Credential Dumping by Pypykatz',
        'Bhabesh Raj',
        'sysmon',
        9,
        'Detects LSASS process access by pypykatz for credential dumping.',
        ARRAY['https://github.com/skelsec/pypykatz'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\lsass.exe') AND (`event_data`.`CallTrace` LIKE '%C:\Windows\SYSTEM32\ntdll.dll+%' AND `event_data`.`CallTrace` LIKE '%C:\Windows\System32\KERNELBASE.dll+%' AND `event_data`.`CallTrace` LIKE '%libffi-7.dll%' AND `event_data`.`CallTrace` LIKE '%_ctypes.pyd+%' AND `event_data`.`CallTrace` LIKE '%python3*.dll+%') AND (`event_data`.`GrantedAccess` = '0x1FFFFF')
)
);


INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', 'process_access', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY['attack.credential_access', 'attack.execution', 'attack.lateral_movement'], ARRAY['t1003', 'attack.t1003', 't1059', 'attack.t1086', 't1021', 'attack.t1028'], ARRAY['attack.t1003.001', 'attack.t1059.001', 'attack.t1021.006']) AS threat,
    ROW('Mimikatz through Windows Remote Management',
        'Patryk Prauze - ING Tech',
        'sysmon',
        7,
        'Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.',
        ARRAY['https://pentestlab.blog/2018/05/15/lateral-movement-winrm/'],
        '1.0', 
        'sysmon') AS `rule`
FROM
    (
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`
    FROM
        sysmon_table
    WHERE
        event_id = 10 AND (`event_data`.`TargetImage` LIKE '%\lsass.exe') AND (`event_data`.`SourceImage` = 'C:\Windows\system32\wsmprovhost.exe')
)
);


END;
