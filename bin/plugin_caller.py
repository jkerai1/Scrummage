import plugins.common.Connectors as Connectors

def Starter(Task_ID):
    Connection = Connectors.Load_Main_Database()
    Cursor = Connection.cursor()
    PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
    Cursor.execute(PSQL_Update_Query, ("Running", int(Task_ID),))
    Connection.commit()

def Stopper(Task_ID):
    Connection = Connectors.Load_Main_Database()
    Cursor = Connection.cursor()
    PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
    Cursor.execute(PSQL_Update_Query, ("Stopped", int(Task_ID),))
    Connection.commit()

class Plugin_Caller:

    def __init__(self, **kwargs):
        self.plugin_name = kwargs["Plugin_Name"]
        self.query = kwargs["Query"]
        self.limit = kwargs["Limit"]
        self.task_id = kwargs["Task_ID"]

    def Call_Plugin(self):
        Starter(self.task_id)

        if self.plugin_name == "YouTube Search":
            import plugins.YouTube_Search as YT_Search
            YT_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Windows Store Search":
            import plugins.Windows_Store_Search as WS_Search
            WS_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Vulners Search":
            import plugins.Vulners_Search as Vulners_Search
            Vulners_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Vehicle Registration Search":
            import plugins.Vehicle_Registration_Search as Vehicle_Registration_Search
            Vehicle_Registration_Search.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Twitter Scraper":
            import plugins.Twitter_Scraper as Twitter_Scrape
            Twitter_Scrape.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "RSS Feed Search":
            import plugins.RSS_Feed_Search as RSS_Feed_Search
            RSS_Feed_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Reddit Search":
            import plugins.Reddit_Search as Reddit_Search
            Reddit_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "PhishTank Search":
            import plugins.Phishtank_Search as Phishtank_Search
            Phishtank_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Pinterest Pin Search":
            import plugins.Pinterest_Search as Pinterest_Search
            Pinterest_Search.Search(self.query, self.task_id, "pin", Limit=self.limit)
            
        elif self.plugin_name == "Pinterest Board Search":
            import plugins.Pinterest_Search as Pinterest_Search
            Pinterest_Search.Search(self.query, self.task_id, "board", Limit=self.limit)
            
        elif self.plugin_name == "Library Genesis Search":
            import plugins.Library_Genesis_Search as Library_Genesis_Search
            Library_Genesis_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "iTunes Store Search":
            import plugins.ITunes_Store_Search as ITunes_Store_Search
            ITunes_Store_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Instagram User Search":
            import plugins.Instagram_Search as Instagram_Search
            Instagram_Search.Search(self.query, self.task_id, "User")
            
        elif self.plugin_name == "Instagram Tag Search":
            import plugins.Instagram_Search as Instagram_Search
            Instagram_Search.Search(self.query, self.task_id, "Tag")
            
        elif self.plugin_name == "Instagram Media Search":
            import plugins.Instagram_Search as Instagram_Search
            Instagram_Search.Search(self.query, self.task_id, "Media")
            
        elif self.plugin_name == "Instagram Location Search":
            import plugins.Instagram_Search as Instagram_Search
            Instagram_Search.Search(self.query, self.task_id, "Location")
            
        elif self.plugin_name == "Have I Been Pwned - Password Search":
            import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
            Have_I_Been_Pwned.Search(self.query, self.task_id, "password")
            
        elif self.plugin_name == "Have I Been Pwned - Email Search":
            import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
            Have_I_Been_Pwned.Search(self.query, self.task_id, "email")
            
        elif self.plugin_name == "Have I Been Pwned - Breach Search":
            import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
            Have_I_Been_Pwned.Search(self.query, self.task_id, "breach")
            
        elif self.plugin_name == "Have I Been Pwned - Account Search":
            import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
            Have_I_Been_Pwned.Search(self.query, self.task_id, "account")
            
        elif self.plugin_name == "Google Search":
            import plugins.Google_Search as Google_Search
            Google_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Google Play Store Search":
            import plugins.Google_Play_Store_Search as Google_Play_Store_Search
            Google_Play_Store_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Ebay Search":
            import plugins.Ebay_Search as Ebay_Search
            Ebay_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Domain Fuzzer - Regular Domain Suffixes":
            import plugins.Domain_Fuzzer as Domain_Fuzzer
            Domain_Fuzzer.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Domain Fuzzer - Global Domain Suffixes":
            import plugins.Domain_Fuzzer as Domain_Fuzzer
            Domain_Fuzzer.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Domain Fuzzer - Alpha-Linguistic Character Switcher":
            import plugins.Domain_Fuzzer as Domain_Fuzzer
            Domain_Fuzzer.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Domain Fuzzer - All Extensions":
            import plugins.Domain_Fuzzer as Domain_Fuzzer
            Domain_Fuzzer.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Ahmia Darkweb Search":
            import plugins.Ahmia_Darkweb_Search as Ahmia_Darkweb_Search
            Ahmia_Darkweb_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Craigslist Search":
            import plugins.Craigslist_Search as Craigslist_Search
            Craigslist_Search.Search(self.query, self.task_id, Limit=self.limit)
            
        elif self.plugin_name == "Certificate Transparency":
            import plugins.Certificate_Transparency as Certificate_Transparency
            Certificate_Transparency.Search(self.query, self.task_id)
            
        elif self.plugin_name == "Blockchain Ethereum Transaction Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Transaction_Search(self.query, self.task_id, "eth")
            
        elif self.plugin_name == "Blockchain Bitcoin Cash Transaction Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Transaction_Search(self.query, self.task_id, "bch")
            
        elif self.plugin_name == "Blockchain Bitcoin Transaction Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Transaction_Search(self.query, self.task_id, "btc")
            
        elif self.plugin_name == "Blockchain Ethereum Address Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Address_Search(self.query, self.task_id, "eth")
            
        elif self.plugin_name == "Blockchain Bitcoin Cash Address Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Address_Search(self.query, self.task_id, "bch")
            
        elif self.plugin_name == "Blockchain Bitcoin Address Search":
            import plugins.Blockchain_Search as Blockchain_Search
            Blockchain_Search.Address_Search(self.query, self.task_id, "btc")
            
        Stopper(self.task_id)
        
if __name__ == "__main__":
    import argparse, sys, plugins.common.General as General
    Parser = argparse.ArgumentParser(description='Plugin Caller calls Scrummage plugins.')
    Parser.add_argument('-t', '--task', help='This option is used to specify a task ID to run. ./plugin_caller.py -t 1')
    Arguments = Parser.parse_args()

    Task_ID = 0

    if Arguments.task:

        try:
            Task_ID = int(Arguments.task)
            Connection = Connectors.Load_Main_Database()
            cursor = Connection.cursor()
            PSQL_Select_Query = 'SELECT * FROM tasks WHERE task_id = %s;'
            cursor.execute(PSQL_Select_Query, (Task_ID,))
            result = cursor.fetchone()

            if result:
                print(result[2])
                print(result[5])
                Plugin_to_Call = Plugin_Caller(Plugin_Name=result[2], Limit=result[5], Task_ID=Task_ID, Query=result[1])
                Plugin_to_Call.Call_Plugin()

        except:
            sys.exit("[-] Invalid Task ID, please provide a valid Task ID")
