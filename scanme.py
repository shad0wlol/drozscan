#!/usr/bin/env python

import subprocess
import json
from colorama import Fore
from bs4 import BeautifulSoup
import sys

class drozscan:
    
    def __init__(self):
        self.drozer_installed = False
        self.drozer_installed = self.is_tool_installed("drozer")
        if not self.drozer_installed:
            print("drozer is not installed. Please install it")
            
    __author__ = 'themalwarenews ( @themalwarenews) '
    inspiration = "interference-security"


    def is_tool_installed(self, tool_name):
        # Code to check if a tool is installed
        try:
            subprocess.run([tool_name, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            return False
    
    def welcome(self):
        __banner__ = '''\t 
                                                                                                    
        \t@@@@@@@   @@@@@@@    @@@@@@   @@@@@@@@              @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  
        \t@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@             @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  
        \t@@!  @@@  @@!  @@@  @@!  @@@       @@!             !@@       !@@       @@!  @@@  @@!@!@@@  
        \t!@!  @!@  !@!  @!@  !@!  @!@      !@!              !@!       !@!       !@!  @!@  !@!!@!@!  
        \t@!@  !@!  @!@!!@!   @!@  !@!     @!!    @!@!@!@!@  !!@@!!    !@!       @!@!@!@!  @!@ !!@!  
        \t!@!  !!!  !!@!@!    !@!  !!!    !!!     !!!@!@!!!   !!@!!!   !!!       !!!@!!!!  !@!  !!!  
        \t!!:  !!!  !!: :!!   !!:  !!!   !!:                      !:!  :!!       !!:  !!!  !!:  !!!  
        \t:!:  !:!  :!:  !:!  :!:  !:!  :!:                      !:!   :!:       :!:  !:!  :!:  !:!  
        \t :::: ::  ::   :::  ::::: ::   :: ::::             :::: ::    ::: :::  ::   :::   ::   ::  
        \t:: :  :    :   : :   : :  :   : :: : :             :: : :     :: :: :   :   : :  ::    :   
                                                                                                
        '''
        print("\n")
        print(Fore.RED + " \t \t Automated drozer to test the android components Security\n")
        print(Fore.GREEN + __banner__)
        print("      ------------------------------------------------------------------")
        print("\n     | TOOL          :  DROZER-SCANNER\t\t\t\t        |")
        print("     | AUTHOR        :  " + self.__author__ + "      \t|")
        print("     | Inspiration   :  " + self.inspiration + "       \t\t\t|")
        print("     | VERSION       :  1.1   [edited by @shad0wlol]\t \t\t|\n")
        print("      ------------------------------------------------------------------")
        print("\n\n")
        print(Fore.RED + "\t NOTE: MAKE SURE YOU HAVE TURNED ON YOUR ANDROID VIRTUAL DEVICE / REAL DEVICE AND CONNECTED VIA ADB")


    def perform_scan(self, query_type, p_name, a=0):
        try:
            drozer_command = 'drozer console connect -c "run ' + str(query_type) + (' ' + str(p_name) if a == 0 else '') + '"'
            process = subprocess.Popen(drozer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, universal_newlines=True)
            input, output = process.stdin, process.stdout
            process_data = output.read()
            input.close()
            output.close()
            process.wait()

            if "could not find the package" in process_data:
                process_data = 'Invalid Package'

            return process_data
        except Exception as e:
            print(f"Error performing scan: {e}")
            return 'Error performing scan'


    def format_data(self, task, result, json_results):
        separator = ("*" * 50)
        print(Fore.GREEN + "\n%s:\n%s\n%s" % (task, separator, result))
        result = result.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\n", "<br>").replace("\\r", "")
        json_results[str(task)] = result


    def get_package_name(self):
        if len(sys.argv) > 1:
            p_name = sys.argv[1]
        else:
            p_name = input("\t[+] The Package name is: ")
            if not p_name:
                print("Package name cannot be empty.")
                exit(1)
        return p_name


    def get_file_name(self):
        file_name = input("\n [+] Enter the file name to store the results: ")
        if not file_name:
            print("File name cannot be empty.")
            exit(1)
        return file_name
        
    def custom_print(self, text, file):
        print(text)  # Print to terminal
        print(text, file=file)  # Print to file

    def main(self):
        self.welcome()
        p_name = self.get_package_name()
        file_name = self.get_file_name()
        f_json = file_name + ".json"
        f_html = file_name + ".html"
        # Added output to .txt
        f_txt = file_name + ".txt"
        
        with open(f_txt, 'w') as file:
            separator = (("_" * 100) + "\n")
            results_json = {}
        
            # Example: Get Package complete Info
            package_info = self.perform_scan('app.package.info -a', p_name)
            self.format_data("Package Information", package_info, results_json)
            self.custom_print(separator, file)
        
            queries = [
                ('app.package.info -a', 'Package Information'),
                ('app.activity.info -i -u -a', 'Activities Information'),
                ('app.broadcast.info -i -u -a', 'Broadcast Receivers Information'),
                ('app.package.attacksurface', 'Attack Surface Information'),
                ('app.package.backup -f', 'Package with Backup API Information'),
                ('app.package.manifest', 'Android Manifest File'),
                ('app.package.native', 'Native Libraries used'),
                ('app.provider.info -u -a', 'Content Provider Information'),
                ('app.provider.finduri', 'Content Provider URIs'),
                ('app.service.info -i -u -a', 'Services Information'),
                ('scanner.misc.native -a', 'Native Components in Package'),
                ('scanner.misc.readablefiles /data/data/'+p_name+'/', 'World Readable Files in App Installation Location'),
                ('scanner.misc.readablefiles /data/data/'+p_name+'/', 'World Writeable Files in App Installation Location'),
                ('scanner.provider.finduris -a', 'Content Providers Query from Current Context'),
                ('scanner.provider.injection -a', 'SQL Injection on Content Providers'),
                ('scanner.provider.sqltables -a', 'SQL Tables using SQL Injection'),
                ('scanner.provider.traversal -a', 'Directory Traversal using Content Provider'),
        ]
            for query, description in queries:
                result = self.perform_scan(query, p_name)
                self.format_data(description, result, results_json)
                self.custom_print(Fore.GREEN + separator, file)
        
            # Create HTML using BeautifulSoup
            soup = BeautifulSoup("<html><head><title>APP Analysis Report </title><style>body { background-color: black; color: green; }</style></head><body></body></html>", 'html.parser')
            body = soup.body
            h1 = soup.new_tag("h1", style="text-align: center; color: green;")
            h1.string = "Drozer Analysis Report"
            body.append(h1)
        
            # Add results to HTML
            for task, result in results_json.items():
                table = soup.new_tag("table", style="border-style: solid; width: 100%; margin-left: auto; margin-right: auto; color: green;", border="1", width="100%")
                tbody = soup.new_tag("tbody")
                tr1 = soup.new_tag("tr", style="background: #12294d; color: green; text-align: left;")
                td1 = soup.new_tag("td")
                td1.string = task
                tr1.append(td1)
                tbody.append(tr1)
                tr2 = soup.new_tag("tr")
                td2 = soup.new_tag("td", style="text-align: left; color: green;")
                pre = soup.new_tag("pre", style="line-height: 0.8em; color: green;")
                span = soup.new_tag("span", style="color: green;")
                span.string = result.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\n", "<br>").replace("\\r", "")
                pre.append(span)
                td2.append(pre)
                tr2.append(td2)
                tbody.append(tr2)
                table.append(tbody)
                body.append(table)
                body.append(soup.new_tag("br"))
                body.append(soup.new_tag("br"))
        
            # Write HTML file
            with open(f_html, "w", encoding="utf-8") as file:
                file.write(str(soup))
            
            # Write JSON results
            with open(f_json, "w") as outfile:
                json.dump(results_json, outfile)
        
            self.custom_print("\n All the results are stored in " + file_name + " JSON, TXT, and HTML file..!!!", file)
            self.custom_print(separator, file)


if __name__ == '__main__':
    try:
        scanner = drozscan()
        scanner.main()
    except Exception as e:
        print(f"An error occurred: {e}")
