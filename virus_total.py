import os.path
import json
import requests

# <FILE>------------------------------------------------------------

def scan_file(filename:str, api_key:str) -> dict:
	api_url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
	params = dict(apikey=api_key)
	result = dict()
	if os.path.exists(filename):
		with open(filename, 'rb') as file:
			files = dict(file=(filename, file))
			response = requests.post(api_url_scan, files=files, params=params, timeout=15)
		if response.status_code == 200:
			result = response.json()
	else:
		print("File not exist:")
		exit(1)
	return result #info_dict



def get_report_last_scan(sing:str, api_key:str) -> dict:
	"""
	#Можно передать контрольную сумму вместо 'scan_id'
	:param sing: scan_id или контрольная сумма sha256
	:param api_key: Ключ Virus Total API
	:return: словарь с отчётом
	"""

	api_url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
	params = dict(apikey=api_key, resource=sing)
	response = requests.get(api_url_report, params=params, timeout=15)
	report = ""
	if response.status_code == 200:
		result = response.json()
		report = json.dumps(result, sort_keys=False, indent=4)
	else:
		print("Что-то пошло не так...")
		exit(1)
	return json.loads(report)


def print_report_file(report: dict, detected_only=False):

	print("INFO:")
	print("   scan_id: ", report.get("scan_id"))
	print("   total: ", report.get("total"))
	print("   positives: ", report.get("positives"))
	print("   permalink: ", report.get("permalink"))
	print("   scan_date: ", report.get("scan_date"))
	print("   response_code: ", report.get("response_code"))
	print("   verbose_msg: ", report.get("verbose_msg"))

	print("\nHash sum:")
	print("  sha1: ", report.get("sha1"))
	print("  sha256: ", report.get("sha256"))
	print("  md5: ", report.get("md5"))

	if detected_only:
		report['scans'] = {k: v for k, v in report['scans'].items() if v['detected']}

	print("\nSCANS:")
	for key in report['scans']:
		print(key)
		print("   Detected", report['scans'][key]['detected'])
		print("   Version: ", report['scans'][key]['version'])
		print("   Result: ", report['scans'][key]['result'])
		print("   Update: ", report['scans'][key]['update'])

# </FILE>------------------------------------------------------------


# <URL>------------------------------------------------------------
def scan_url(url: str, apikey: str) -> dict:
	"""
	Отправка URL на сервер для сканирования
	:param url: ссылка для сканирования
	:param apikey: ключ для АПи Virus Total
	:return: словарь и информацией
	"""
	api_url = "https://www.virustotal.com/vtapi/v2/url/scan"
	params = dict(apikey=apikey, url=url)
	response = requests.post(api_url, data=params, timeout=15)
	if response.status_code == 200:
		result = response.json()
		# print(json.dumps(result, sort_keys=False, indent=4))
		return result

def get_report(url: str, apikey:str) -> dict:
	"""
	Получить отчёт о результатах сканирования URL

	:param url: Адрес ресурса
	:param apikey: ключ API Virus Total
	:return: словарт с отчётом
	"""
	api_url = "https://www.virustotal.com/vtapi/v2/url/report"
	params = dict(apikey=apikey, resource=url, scan=0)
	response = requests.get(api_url, params=params, timeout=15)
	if response.status_code == 200:
		result = response.json()
		#print(json.dumps(result, sort_keys=False, indent=4))
		return result

def print_report_url(report: dict, detected_only=False):
	print("INFO:")
	print(f"   scan_id: {report.get('scan_id')}\n"
	      f"   resource: {report.get('resource')}\n"
	      f"   url: {report.get('url')}\n"
	      f"   response_code: {report.get('response_code')}\n"
	      f"   scan_date: {report.get('scan_date')}\n"
	      f"   permalink: {report.get('permalink')}\n"
	      f"   verbose_msg: {report.get('verbose_msg')}\n"
	      f"   filescan_id: {report.get('filescan_id')}\n"
	      f"   positives: {report.get('positives')}\n"
	      f"   total: {report.get('total')}")

	if detected_only:
		report['scans'] = {k: v for k, v in report['scans'].items() if v['detected']}

	print("\nSCANS:")
	for r in report['scans']:
		print(r)
		print("   Detected", report['scans'][r]['detected'])
		print("   Result: ", report['scans'][r]['result'])

# </URL>------------------------------------------------------------


# <IP>------------------------------------------------------------
def scan_ip(ip: str, apikey: str):
	api_url = "https://www.virustotal.com/vtapi/v2/domain/report"
	params = dict(apikey=apikey, domain=ip)
	response = requests.get(api_url, params=params, timeout=15)
	if response.status_code == 200:
		result = response.json()
		return result
# </IP>------------------------------------------------------------


# <JSON dump>------------------------------------------------------------
def dump_to_json(report:dict, filename:str="report.json"):
	with open(filename, 'a') as file:
		json.dump(report, file)

	f = open(filename, 'a')
	f.write('\n')
	f.close()
# </JSON dump>------------------------------------------------------------

if __name__ == "__main__":
	print("[WARNING] This is a module. Don't using like main-file....")