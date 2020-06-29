#!/usr/bin/env python3
import logging, os, json, requests, re, plugins.common.General as General
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

Plugin_Name = "Phishstats"
The_File_Extensions = {"Main": ".json", "Query": ".html"}

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = int(kwargs["Limit"])

        else:
            Limit = 10

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    Log_File = General.Logging(Directory, Plugin_Name.lower())
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

        try:
            Pull_URL = f"https://phishstats.info:2096/api/phishing?_where=(url,like,~{Query}~)&_sort=-id&_size={Limit}"
            Results = json.loads(requests.get(Pull_URL).text)
            Output_Connections = General.Connections(Query, Plugin_Name, "phishstats.info", "Phishing", Task_ID, Plugin_Name.lower())
            Main_File = General.Main_File_Create(Directory, Plugin_Name, json.dumps(Results, indent=4, sort_keys=True), Query, The_File_Extensions["Main"])

            for Result in Results:
                Current_Link = Result["url"]
                Current_Domain = Current_Link.strip("https://")
                Current_Domain = Current_Domain.strip("http://")
                Current_Domain = Current_Domain.strip("www.")
                Current_Title = Result["title"]
                headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0"}

                try:
                    Current_Result = requests.get(Current_Link, headers=headers, verify=False).text
                    Response_Regex = re.search(r"\<title\>([^\<\>]+)\<\/title\>", Current_Result)
                    Output_file_Query = Query.replace(" ", "-")
                    Output_file = General.Create_Query_Results_Output_File(Directory, Output_file_Query, Plugin_Name, Current_Result, Current_Domain, The_File_Extensions["Query"])

                    if Main_File and Output_file:

                        if Current_Link not in Cached_Data and Current_Link not in Data_to_Cache:

                            if Response_Regex:
                                Current_Title = Response_Regex.group(1)
                                Current_Title = Current_Title.strip()
                                Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, Plugin_Name.lower())

                            else:

                                if not "Phishstats" in Current_Title:
                                    Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, Plugin_Name.lower())

                                else:
                                    Output_Connections.Output([Main_File, Output_file], Current_Link, General.Get_Title(Current_Link), Plugin_Name.lower())

                            Data_to_Cache.append(Current_Link)

                except:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request for result, link may no longer be available.")

        except:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")