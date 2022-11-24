from os import environ
import dotenv

from virus_total import scan_file, get_report_last_scan
from virus_total import print_report_file as print_file_report
from virus_total import scan_url, get_report, print_report_url



if __name__ == "__main__":
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]
	deteccted_only = True

	print("VIrus Total:\n 1) scan file\n 2) scan url\n<any button> cencel\n")
	action = input("enter action:>")
	if action == "1":
		filename = input("Enter a 'file path' :>")
		scan_info = scan_file(filename, key)
		sing = scan_info.get("scan_id")
		report = get_report_last_scan(sing, key)
		print_file_report(report, detected_only=deteccted_only)
	elif action == "2":
		urlname = input("Enter URL :>")
		report_dict = get_report(urlname, key)
		print_report_url(report_dict, detected_only=deteccted_only)
	else:
		print("Aaction canceled")




