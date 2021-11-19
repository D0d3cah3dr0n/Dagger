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
		
		OriginalFileName STRING,
        sha1 STRING,
        EventType STRING,
        WMIcommand STRING,
        EventLog STRING,
        Imphash STRING,
		DestinationPort STRING,
		Initiated STRING,
        `User` STRING,
        DestinationHostname STRING,
        StartModule STRING,
		EventID STRING,
        TargetProcessAddress STRING,
        StartFunction STRING,
        IntegrityLevel STRING,
        `Description` STRING,
        CurrentDirectory STRING,
        Company STRING,
        Product STRING,
        ProcessCommandLine STRING,
        DestinationIp STRING,
        DestinationIsIpv6 STRING,
        SourcePort STRING,
        ParentPrcessName STRING,
        processCommandLine STRING,
        LogonId STRING,
        SubjectLogonId STRING,
		FileVersion STRING,
		ParentUser STRING,

        CommandLine STRING, 
        ParentCommandLine STRING, 
        UtcTime STRING 
    >,
    uuid STRING,
  `timestamp` TIMESTAMP(3) METADATA

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

CREATE TEMPORARY VIEW `tmp_view` AS 
    SELECT
        computer_name,
        host,
        ARRAY[`uuid`] AS event_ids,
        `timestamp`,
        event_id,
        event_data
    FROM
        sysmon_table;


CREATE TEMPORARY VIEW `alert_view` AS
	SELECT
		computer_name,
		host,
		ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
		ROW(ARRAY['attack.execution '],ARRAY[''],ARRAY['t1127.001 ']) AS threat,
		ROW('Silenttrinity Stager Msbuild Activity','Kiran kumar s, oscd.community','sysmon',7,'Detects a possible remote connections to Silenttrinity c2',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\network_connection\silenttrinity_stager_msbuild_activity.yml'],'1.0','sysmon') AS `rule`
	FROM tmp_view
	WHERE (event_id=3) AND ( ( ( `event_data`.ParentImage LIKE  '%\msbuild.exe'  )  ) and ( ( `event_data`.Initiated = 'true' )  AND ( `event_data`.DestinationPort =  '80'  OR `event_data`.DestinationPort =  '443'  )  )  )

UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY['t1218 '],ARRAY['']) AS threat,  ROW('Custom Class Execution via Xwizard','Ensar Şamil, @sblmsrsn, @oscd_initiative','sysmon',5,'Detects the execution of Xwizard tool with specific arguments which utilized to run custom class properties.',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_class_exec_xwizard.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.`Image` LIKE  '%\xwizard.exe'  )  AND ( `event_data`.CommandLine SIMILAR TO  '{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}'  )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY['t1216 '],ARRAY['']) AS threat,  ROW('Execution via CL_Invocation.ps1','oscd.community, Natalia Shornikova','sysmon',7,'Detects Execution via SyncInvoke in CL_Invocation.ps1 module',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_cl_invocation_lolscript.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE  '%CL_Invocation.ps1%'  AND `event_data`.CommandLine LIKE  '%SyncInvoke%'  )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY['t1216 '],ARRAY['']) AS threat,  ROW('Execution via CL_Mutexverifiers.ps1','oscd.community, Natalia Shornikova','sysmon',7,'Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_cl_mutexverifiers_lolscript.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE  '%CL_Mutexverifiers.ps1%'  AND `event_data`.CommandLine LIKE  '%runAfterCancelProcess%'  )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.credential_access '],ARRAY['t1003 '],ARRAY['t1003.005 ']) AS threat,  ROW('Cmdkey Cached Credentials Recon','jmallette','sysmon',5,'Detects usage of cmdkey to look for cached credentials',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_cmdkey_recon.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE '% /list%'  )  AND ( `event_data`.`Image` LIKE  '%\cmdkey.exe'  )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.execution attack.defense_evasion attack.privilege_escalation '],ARRAY['t1088 t1191 '],ARRAY['t1548.002 t1218.003 ']) AS threat,  ROW('CMSTP UAC Bypass via COM Object Access','Nik Seetharaman, Christian Burkard','sysmon',7,'Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects (e.g. UACMe ID of 41, 43, 58 or 65)',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_cmstp_com_object_access.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.ParentImage LIKE  '%\DllHost.exe'  )  AND ( `event_data`.IntegrityLevel =  'High'  OR `event_data`.IntegrityLevel =  'System'  )  AND ( `event_data`.ParentCommandLine LIKE  '% /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}%'  OR `event_data`.ParentCommandLine LIKE  '% /Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}%'  OR `event_data`.ParentCommandLine LIKE  '% /Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}%'  OR `event_data`.ParentCommandLine LIKE  '% /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}%'  OR `event_data`.ParentCommandLine LIKE  '% /Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}%'  )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY['t1036 '],ARRAY['t1036.005 ']) AS threat,  ROW('Suspicious Svchost Process','Florian Roth','sysmon',7,'Detects a suspicious svchost process start',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_susp_svchost.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.`Image` LIKE  '%\svchost.exe'  )  ) and not ( ( `event_data`.ParentImage LIKE  '%\services.exe'  OR `event_data`.ParentImage LIKE  '%\MsMpEng.exe'  OR `event_data`.ParentImage LIKE  '%\Mrt.exe'  OR `event_data`.ParentImage LIKE  '%\rpcnet.exe'  OR `event_data`.ParentImage LIKE  '%\svchost.exe'  )  ) and not ( ( `event_data`.ParentImage = 'null' )  )  )    	
UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion attack.privilege_escalation '],ARRAY['t1055 '],ARRAY['']) AS threat,  ROW('Suspect Svchost Activity','David Burkett','sysmon',9,'It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_susp_svchost_no_cli.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( ( `event_data`.CommandLine LIKE  '%svchost.exe'  )  ) and ( ( `event_data`.`Image` LIKE  '%\svchost.exe'  )  ) ) and not ( ( `event_data`.ParentImage LIKE  '%\rpcnet.exe'  OR `event_data`.ParentImage LIKE  '%\rpcnetp.exe'  )  OR ( `event_data`.CommandLine = 'null' )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.execution '],ARRAY['t1204 '],ARRAY['']) AS threat,  ROW('Snatch Ransomware','Florian Roth','sysmon',9,'Detects specific process characteristics of Snatch ransomware word document droppers',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_crime_snatch_ransomware.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE  '%shutdown /r /f /t 00%'  OR `event_data`.CommandLine LIKE  '%net stop SuperBackupMan%'  )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.exfiltration attack.collection '],ARRAY['t1002 '],ARRAY['t1560.001 ']) AS threat,  ROW('Data Compressed - rar.exe','Timur Zinniatullin, E.M. Anhaus, oscd.community','sysmon',3,'An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_data_compressed_with_rar.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE '% a %'  )  AND ( `event_data`.`Image` LIKE  '%\rar.exe'  )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY['t1036 '],ARRAY['']) AS threat,  ROW('Detecting Fake Instances Of Hxtsr.exe','Sreeman','sysmon',5,'HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files". Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe". Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_detecting_fake_instances_of_hxtsr.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.`Image` = 'hxtsr.exe' )  ) and not ( ( `event_data`.CurrentDirectory SIMILAR TO  '(?i)c:\\\\program files\\\\windowsapps\\\\microsoft\.windowscommunicationsapps_.*\\\\hxtsr\.exe'  )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion '],ARRAY[''],ARRAY['t1574.002 ']) AS threat,  ROW('Xwizard DLL Sideloading','Christian Burkard','sysmon',7,'Detects the execution of Xwizard tool from the non-default directory which can be used to sideload a custom xwizards.dll',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_dll_sideload_xwizard.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.`Image` LIKE  '%\xwizard.exe'  )  ) and not ( ( `event_data`.`Image` LIKE 'C:\Windows\System32\%'  )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.defense_evasion attack.execution '],ARRAY['t1047 t1220 t1059 '],ARRAY['t1059.005 t1059.007 ']) AS threat,  ROW('SquiblyTwo','Markus Neis / Florian Roth','sysmon',5,'Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_bypass_squiblytwo.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE  '%wmic%'  AND `event_data`.CommandLine LIKE  '%format%'  AND `event_data`.CommandLine LIKE  '%http%'  )  AND ( `event_data`.`Image` LIKE  '%\wmic.exe'  )  ) or ( ( `event_data`.Imphash =  '1B1A3F43BF37B5BFE60751F2EE2F326E'  OR `event_data`.Imphash =  '37777A96245A3C74EB217308F3546F4C'  OR `event_data`.Imphash =  '9D87C9D67CE724033C0B40CC4CA1B206'  )  AND ( `event_data`.CommandLine LIKE  '%format:%'  AND `event_data`.CommandLine LIKE  '%http%'  )  )  )    	
--UNION ALL  	SELECT  computer_name,  host,  ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,  ROW(ARRAY['attack.persistence '],ARRAY['t1042 '],ARRAY['t1546.001 ']) AS threat,  ROW('Change Default File Association','Timur Zinniatullin, oscd.community','sysmon',3,'When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.',ARRAY['C:\Users\hui.zhou\Downloads\sigma-master\rules\windows\process_creation\win_change_default_file_association.yml'],'1.0','sysmon') AS `rule`  	FROM tmp_view  	WHERE (event_id=1) AND ( ( ( `event_data`.CommandLine LIKE  '%cmd%'  AND `event_data`.CommandLine LIKE  '%/c%'  AND `event_data`.CommandLine LIKE  '%assoc%'  )  )  )    	



;

INSERT INTO alert_table select * from alert_view;

