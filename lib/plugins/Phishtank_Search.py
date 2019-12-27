#!/usr/bin/env python3
from bs4 import BeautifulSoup
import logging, os, requests, plugins.common.General as General

Plugin_Name = "PhishTank"
The_File_Extension = ".html"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if kwargs.get('Limit'):

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

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
            Pull_URL = "https://www.phishtank.com/target_search.php?target_id=" + Query + "&valid=y&active=All&Search=Search"
            Content = requests.get(Pull_URL).text
            soup = BeautifulSoup(Content, features="lxml")
            tds = soup.findAll('td')
            Links = []

            for td in tds:
                link = td.find('a')

                if link and 'phish_detail.php?phish_id=' in link.attrs['href']:
                    Full_Link = "https://www.phishtank.com/" + link.attrs['href']
                    Links.append(Full_Link)

            Current_Step = 0

            for Link in Links:
                Current_Content = requests.get(Link).text
                Current_Soup = BeautifulSoup(Current_Content, features="lxml")
                Spans = Current_Soup.find('span', {"style": "word-wrap:break-word;"})
                Current_Link = Spans.string

                if Current_Link:

                    try:
                        Phish_Site_Response = requests.get(Current_Link).text
                        Output_file_query = Query.replace(" ", "-")
                        Output_file = General.Create_Query_Results_Output_File(Directory, Output_file_query, Plugin_Name, Phish_Site_Response, Link.replace("https://www.phishtank.com/phish_detail.php?phish_id=", ""), The_File_Extension)

                        if Output_file:

                            if Current_Link not in Cached_Data and Current_Link not in Data_to_Cache and Current_Step < int(Limit):
                                General.Connections(Output_file, Query, Plugin_Name, Current_Link, "phishtank.com", "Phishing", Task_ID, General.Get_Title(Current_Link), Plugin_Name.lower())
                                Data_to_Cache.append(Current_Link)
                                Current_Step += 1

                    except:
                        logging.warning(General.Date() + " - " + __name__ + " - Failed to make request for result, link may no longer be available.")

        except:
            logging.warning(General.Date() + " - " + __name__ + " - Failed to make request.")

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")