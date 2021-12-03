#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: lo0o.xing@gmail.com

import os
import re
import yaml


def arr2str(arr: list) -> str:
    s = "', '".join(arr)
    return "'" + s + "'"


def get_attack_tech(tags: list) -> (str, str, str):
    atk_tech = ['attack.reconnaissance', 'attack.resource_development', 'attack.initial_access', 'attack.execution',
                'attack.persistence', 'attack.privilege_escalation', 'attack.defense_evasion',
                'attack.credential_access', 'attack.credential_access', 'attack.discovery', 'attack.lateral_movement',
                'attack.collection', 'attack.command_and_control', 'attack.exfiltration', 'attack.impact']
    tactic = list()
    technique = list()
    subtechnique = list()
    for tag in tags:
        if tag in atk_tech:
            tactic.append(tag)
        elif re.match(r'^attack\.t[0-9]+$', tag) is not None:
            technique.append(tag)
        elif re.match(r'^attack\.t[0-9]+\.[0-9]+$', tag) is not None:
            technique.append(tag.split('.')[1])
            subtechnique.append(tag)
    return arr2str(tactic), arr2str(technique), arr2str(subtechnique)


def trans_flink_sql(key: str, cond: str, value) -> str:
    cond = cond.replace('base64offset|', '')
    if cond == "contains":
        if isinstance(value, str):
            return "`event_data`.`%s` LIKE '%%%s%%'" % (key, value.strip("*"))
        elif isinstance(value, list):
            return "(%s)" % ') OR ('.join(
                list(map(lambda x: "`event_data`.`%s` LIKE '%%%s%%'" % (key, x.lstrip("*")), value)))
        else:
            raise Exception("sigma value type not support")
    elif cond == "endswith":
        if isinstance(value, str):
            return "`event_data`.`%s` LIKE '%%%s'" % (key, value.lstrip("*"))
        elif isinstance(value, list):
            return "(%s)" % ') OR ('.join(list(map(lambda x: "`event_data`.`%s` LIKE '%%%s'" % (key, x.lstrip("*")), value)))
        else:
            raise Exception("sigma value type not support")
    elif cond == "startswith":
        if isinstance(value, str):
            return "`event_data`.`%s` LIKE '%s%%'" % (key, value.rstrip("*"))
        elif isinstance(value, list):
            return "(%s)" % ') OR ('.join(list(map(lambda x: "`event_data`.`%s` LIKE '%s%%'" % (key, x.rstrip("*")), value)))
        else:
            raise Exception("sigma value type not support")
    elif cond == "re":
        if isinstance(value, str):
            return "`event_data`.`%s` SIMILAR TO '%s'" % (key, value)
        elif isinstance(value, list):
            return "(%s)" % ') OR ('.join(list(map(lambda x: "`event_data`.`%s` SIMILAR TO '%s'" % (key, x), value)))
        else:
            raise Exception("sigma value type not support")
    elif cond == "contains|all":
        return ' AND '.join(list(map(lambda x: "`event_data`.`%s` LIKE '%%%s%%'" % (key, x), value)))
    else:
        raise Exception("sigma condition not found!")


def proc_of_conditon(cond: str, sel_dict: dict) -> str:
    cond = cond.lstrip('(').rstrip(')')
    if cond.startswith("1OF") and cond.endswith("*"):
        t = cond[3:-1]
        cl = list()
        for sel in sel_dict:
            if sel.startswith(t):
                cl.append(sel_dict[sel])
        return "(%s)" % ') OR ('.join(cl)
    elif cond == "1OFTHEM":
        cl = list()
        for sel in sel_dict:
            cl.append(sel_dict[sel])
        return "(%s)" % ') OR ('.join(cl)
    else:
        return sel_dict[cond]


def get_where(log_cate: str, detection: dict) -> str:
    if log_cate == 'process_access':
        prex_c = 'event_id = 10 AND'
    elif log_cate == 'process_creation':
        prex_c = 'event_id = 1 AND'
    else:
        prex_c = ''
    condition_str = detection['condition'].replace('1 of ', '1of').upper()

    #if '|' in condition_str:
    #    timeframe = detection['timeframe']
    #    del detection['timeframe']
    #    c = condition_str.split('|')
    #    condition_str = c[0]
    #    timecond = c[1]
    condition = condition_str.split()
    del detection['condition']
    sel_dict = dict()
    for k in detection:
        selection = detection[k]
        selects = list()
        for field in selection:
            if isinstance(selection, list):
                if isinstance(field, dict):
                    key = list(field.keys())[0]
                    value = list(field.values())[0]
                #elif isinstance(field, str):
                else:
                    continue
            else:
                key = field
                value = selection[field]
            if '|' not in field:
                if isinstance(value, str):
                    selects.append("`event_data`.`%s` = '%s'" % (key, value))
                elif isinstance(value, list):
                    s = arr2str(value)
                    selects.append("`event_data`.`%s` IN (%s)" % (key, s))
                elif value is None:
                    selects.append("`event_data`.`%s` IS NULL" % (key))
                else:
                    raise Exception("sigma value type not support")
            else:
                field_arr = field.split('|', 1)
                sql = trans_flink_sql(field_arr[0], field_arr[1], value)
                selects.append(sql)
        sel_dict[k.upper()] = '(%s)' % ') AND ('.join(selects)
    if len(condition) == 1:
        condition_final = proc_of_conditon(condition[0], sel_dict)
    else:
        for c in condition:
            if c in sel_dict or c.startswith('1OF'):
                condition[condition.index(c)] = proc_of_conditon(c, sel_dict)
        condition_final = '(%s)' % ' '.join(condition)
    return prex_c + ' ' + condition_final


def gen_flink_sql(title: str, author: str, level: str, desc: str, refer: str, tactic: str, technique: str, subtechnique: str, where: str) -> str:
    return """
INSERT INTO
alert_table ( computer_name, host, event, threat, rule) (
SELECT
    computer_name,
    host,
    ROW('signal', event_ids, 1, `timestamp`, `timestamp`, `timestamp`) AS `event`,
    ROW(ARRAY[""" + tactic + """], ARRAY[""" + technique + """], ARRAY[""" + subtechnique + """]) AS threat,
    ROW('""" + title + """',
        '""" + author + """',
        'sysmon',
        """ + level + """,
        '""" + desc + """',
        ARRAY[""" + refer + """],
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
        """ + where + """
)
);
"""


def parse(context: dict) -> str:
    def severity_level(le: str) -> str:
        level = {
            'critical': '9',
            'high': '7',
            'medium': '5',
            'low': '3'
        }
        return level.get(le, None)

    if 'tags' in context:
        tactic, technique, subtechnique = get_attack_tech(context['tags'])
    else:
        tactic = technique = subtechnique = ''
    log_cate = context['logsource']['category'] if 'logsource' in context and 'category' in context['logsource'] else ''
    if 'timeframe' in context['detection']:
        return ''
    where = get_where(log_cate, context['detection'])
    refer = context['references'] if 'references' in context else list()


    return gen_flink_sql(
        context['title'],
        context['author'],
        severity_level(context['level']),
        context['description'],
        arr2str(refer),
        tactic, technique, subtechnique,
        where
    )


def get_rule(fp):
    print(fp)
    with open(fp, 'r') as f:
        context = yaml.safe_load(f.read())
        #print(context)
        par = parse(context)
        print(par)


def walk_path(path: str):
    g = os.walk(path)
    for path, l, f in g:
        for fn in f:
            get_rule(os.path.join(path, fn))


if __name__ == '__main__':
    path = "./sigma-master/rules/windows/process_creation/"
    walk_path(path)