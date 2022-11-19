from os import environ
import os.path
import dotenv
import json
import requests



if __name__ == "__main__":
	dotenv.load_dotenv('.env')
	key = environ["vt_api"]
	api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
	filename = input("Enter a 'file path' :>")
	params = dict(apikey=key)
	if os.path.exists(filename):
		with open(filename, 'rb') as file:
			files = dict(file=(filename, file))
			response = requests.post(api_url, files=files, params=params)
		if response.status_code == 200:
			result = response.json()
			print(json.dumps(result, sort_keys=False, indent=4))
	else:
		print("File not found...")