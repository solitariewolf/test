import argparse
import requests
import re
import random

def find_forms(url):
    forms = []
    headers = {
        'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500, 600)}.{random.randint(0, 99)} (KHTML, like Gecko) Chrome/{random.randint(80, 90)}.{random.randint(0, 9)}.{random.randint(1000, 9999)}.{random.randint(10, 99)} Safari/{random.randint(500, 600)}.{random.randint(0, 99)}'
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return None
    form_tags = re.findall(r'<form[^>]*>.*?</form>', response.text, flags=re.DOTALL)
    for form in form_tags:
        form_details = {}
        form_details['action'] = re.search(r'action=".*?"', form).group(0)
        form_details['method'] = re.search(r'method=".*?"', form).group(0)
        input_tags = re.findall(r'<input[^>]*>', form)
        form_details['inputs'] = []
        for input_tag in input_tags:
            input_details = {}
            input_details['type'] = re.search(r'type=".*?"', input_tag).group(0)
            input_details['name'] = re.search(r'name=".*?"', input_tag).group(0)
            input_details['value'] = re.search(r'value=".*?"', input_tag).group(0)
            form_details['inputs'].append(input_details)
        forms.append(form_details)
    return forms

def test_form(url, form):
    vulnerable_inputs = []
    for input_tag in form['inputs']:
        for payload in payloads:
            payload_value = f'{payload}{input_tag["value"]}{payload}'
            data = {
                input_tag['name']: payload_value
            }
            response = requests.post(url, data=data)
            if payload in response.text:
                vulnerable_inputs.append(input_tag['name'])
                break
    if vulnerable_inputs:
        print(f"\033[91mVulnerable form inputs found on {url} form action: {form['action']}, method: {form['method']}, inputs: {vulnerable_inputs}\033[0m")
    else:
        print(f"\033[92mNo vulnerable form inputs found on {url} form action: {form['action']}, method: {form['method']}\033[0m")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search for forms in web pages')
    parser.add_argument('file', type=str, help='The file containing the URLs to check')
    parser.add_argument('-p', '--payloads', type=str, default='payloads.txt', help='The file containing the payloads to test')
    args = parser.parse_args()

    with open(args.file) as f:
        urls = f.read().splitlines()
            for form in forms:
                print(f'\033[92mForm found on {url}:\033[0m')
                print(f'  \033[96mAction:\033[0m {form["action"]}')
                answer = input('Do you want to test the payloads on this form? (y/n) ')
                if answer.lower() == 'y':
                    with open(args.payloads) as f:
                        payloads = f.read().splitlines()
                    test_form(url, form, payloads)
    for form in forms:
        form_data = {}
        for input_tag in form['inputs']:
            if input_tag['type'] == 'submit':
                continue
            name = input_tag['name']
            value = input_tag['value'] if input_tag['value'] else ''
            form_data[name] = value
        for payload in payloads:
            data = form_data.copy()
            for input_tag in data:
                input_tag_value = data[input_tag]
                data[input_tag] = f'{payload}{input_tag_value}{payload}'
            response = requests.post(url, data=data)
            if payload in response.text:
                print(f"\033[91mXSS vulnerability detected on {url} form action: {form['action']}, method: {form['method']}, payload: {payload}\033[0m")
                break
else:
    print(f'\033[92mNo forms found on {url}\033[0m')

with open('vulnerable_urls.txt', 'w') as f:
    for url in vulnerable_urls:
        f.write(url + '\n')

