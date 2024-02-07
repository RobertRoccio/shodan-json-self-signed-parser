import json
import csv
import sys
import datetime

HEADER=['Asset IP Address','Certificate CN','Certificate Org','Hostname','Domains','Organization','Issued On','Expires On','Expired','TLS Versions','Tags']

def parse_tls_list(raw_list):
    result=''
    for version_entry in raw_list:
        if version_entry[0]=='T':
            result = result + version_entry + ","
    if result[-1] == ",":
        result = result[:-1]
    return result

def parse_time(time_str):
    time_str = time_str[:-1]
    result=datetime.datetime.strptime(time_str, "%Y%m%d%H%M%S")
    return result

def main():
    try:
        print("Opening...\n")
        if len(sys.argv) < 2:
            raise FileNotFoundError
        with open(sys.argv[1], 'r') as file:
            data = json.load(file)
            print("JSON loaded...\n")
            results_csv=open('results.csv','w')
            csv_writer=csv.writer(results_csv)
            csv_writer.writerow(HEADER)
            for match in data['matches']:
                columns = []
                columns.append(match['ip_str'])
                columns.append(match['ssl']['cert']['subject']['CN'])
                columns.append(match['ssl']['cert']['subject']['O'])
                #Hostnames
                hostnames = ''
                for hostname in match['hostnames']:
                    hostnames = hostnames + hostname + ', '
                columns.append(hostnames)
                #Domains
                domains = ''
                for domain in match['domains']:
                    domains = domains + domain + ', '
                columns.append(domains)
                
                columns.append(match['org'])
                columns.append(parse_time(match['ssl']['cert']['issued']))
                columns.append(parse_time(match['ssl']['cert']['expires']))
                columns.append(match['ssl']['cert']['expired'])
                columns.append(parse_tls_list(match['ssl']['versions']))
                #Tags
                tags = ''
                for tag in match['tags']:
                    tags = tags + tag + ', '
                columns.append(tags)
                #Close CSV
                csv_writer.writerow(columns)
            results_csv.close()
    except FileNotFoundError:
        print("File not Found")
    
if __name__ == "__main__":
    main()