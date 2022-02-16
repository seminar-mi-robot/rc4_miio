import json
import rc4mi_lib
ssecurity = '' # Security key
har_file = '' # HAR input file
save_file = '' # Output file
with open(har_file, 'r') as f:
    har_data = json.load(f)
    for i, entry in enumerate(har_data['log']['entries']):
        is_rc4 = False
        for header_entry in entry['request']['headers']:
            if header_entry['value'] == 'ENCRYPT-RC4':
                is_rc4 = True
                break
        if not is_rc4:
            continue # nothing to decrypt
        else:
            # decrypt request
            data = list(filter(lambda i: i['name'] == 'data', entry['request']['postData']['params']))[0]['value']
            nonce = list(filter(lambda i: i['name'] == '_nonce', entry['request']['postData']['params']))[0]['value']
            decrypted_request = rc4mi_lib.mi_decrypt(data, ssecurity, nonce)
            entry['request']['postData']['params'] = {'name': 'dec_data', 'value': decrypted_request}
            entry['request']['postData']['text'] = 'data={}'.format(decrypted_request)

            # decrypt response
            data = entry['response']['content']['text']
            decrypted_response = rc4mi_lib.mi_decrypt(data, ssecurity, nonce)
            entry['response']['content']['text'] = decrypted_response

            # save changes
            har_data['log']['entries'][i] = entry
    
    # save to file
    with open(save_file, 'w') as f1:
        json.dump(har_data, f1)
