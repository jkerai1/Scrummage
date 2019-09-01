#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests, logging, os, json, re, plugins.common.General as General

Plugin_Name = "Default-Password"
Concat_Plugin_Name = "defaultpassword"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Concat_Plugin_Name)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Concat_Plugin_Name)
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:
        URL_Body = 'https://default-password.info'
        Main_URL = URL_Body + '/' + Query.lower().replace(' ', '-')
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0', 'Accept': 'ext/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}
        Response = requests.get(Main_URL, headers=headers).text
        General.Main_File_Create(Directory, Plugin_Name, Response, Query, The_File_Extension)
        Regex = re.findall(r'\<tr\>\s+\<td\sclass\=\"name\"\>\s+\<a\shref\=\"([\/\d\w\-\+\?\.]+)\"\>([\/\d\w\-\+\?\.\(\)\s\,\;\:\~\`\!\@\#\$\%\^\&\*\[\]\{\}]+)\<\/a\>\s+\<\/td\>', Response)

        if Regex:
            Current_Step = 0

            for URL, Title in Regex:
                Item_URL = URL_Body + URL
                Current_Response = requests.get(Item_URL, headers=headers).text
                Current_Item_Regex = re.search(r'\<button\sclass\=\"btn\sbtn\-primary\spassword\"\s+data\-data\=\"([\-\d\w\?\/]+)\"\s+data\-toggle\=\"modal\"\s+data\-target\=\"\#modal\"\s+\>show\sme\!\<\/button\>', Current_Response)

                if Current_Item_Regex:

                    try:
                        Detailed_Item_URL = URL_Body + Current_Item_Regex.group(1)
                        Detailed_Response = requests.get(Detailed_Item_URL, headers=headers).text
                        JSON_Response = json.loads(Detailed_Response)

                        if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Response['data'], Title, The_File_Extension)

                            if Output_file:
                                General.Connections(Output_file, Query, Plugin_Name, Item_URL, "default-password.info", "Data Leakage", Task_ID, General.Get_Title(Item_URL), Concat_Plugin_Name)

                            Data_to_Cache.append(Item_URL)
                            Current_Step += 1
                    except:
                        logging.warning(General.Date() + " Failed to generate output, may have a blank detailed response.")

                else:
                    logging.warning(General.Date() + " Failed to match regular expression for current result.")

        else:
            logging.warning(General.Date() + " Failed to match regular expression for Query.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")