import requests, logging
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings

CLIENT_ID = settings.CLIENT_ID
CLIENT_SECRET = settings.CLIENT_SECRET
REDIRECT_URI = 'http://localhost:8000/callback'
TOKEN_URL = 'https://accounts.zoho.in/oauth/v2/token'

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def login(request):
    """ Redirect to Zoho login for OAuth """
    auth_url = f"https://accounts.zoho.in/oauth/v2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=ZohoCRM.modules.ALL&access_type=offline"
    return redirect(auth_url)

def callback(request):
    """ Handle OAuth callback and exchange code for tokens """
    code = request.GET.get('code')
    token_data = {
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
    }
    logging.debug(f"Requesting token with client_id: {CLIENT_ID}")
    response = requests.post(TOKEN_URL, data=token_data)
    try:
        tokens = response.json()
    except ValueError:
        logging.error("Failed to decode token response.")
        return render(request, 'index.html', {'error': 'Failed to decode token response.'})
    
    if 'access_token' in tokens and 'refresh_token' in tokens:
        request.session['access_token'] = tokens['access_token']
        request.session['refresh_token'] = tokens['refresh_token']
        logging.debug(f"Access token: {tokens['access_token']}")
        logging.debug(f"Refresh token: {tokens['refresh_token']}")
        return redirect('index')
    else:
        logging.error(f"Failed to get access token: {tokens.get('error', 'Unknown error')}")
        return render(request, 'index.html', {'error': 'Failed to get access token'})

def refresh_token(request):
    """ Refresh the access token using the refresh token """
    refresh_token = request.session.get('refresh_token')
    if not refresh_token:
        logging.error("No refresh token found in session.")
        raise Exception("No refresh token found in session.")
    
    token_data = {
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
    }
    logging.debug(f"Refreshing token with client_id: {CLIENT_ID}")
    response = requests.post(TOKEN_URL, data=token_data)
    try:
        tokens = response.json()
    except ValueError:
        logging.error("Failed to decode token response.")
        raise Exception("Failed to decode token response.")
    
    if 'access_token' in tokens:
        request.session['access_token'] = tokens['access_token']
        return tokens['access_token']
    else:
        error_message = f"Failed to refresh access token: {tokens.get('error', 'Unknown error')}"
        logging.error(error_message)
        raise Exception(error_message)

def get_access_token(request):
    """ Retrieve the current access token or refresh it if expired """
    access_token = request.session.get('access_token')
    print(access_token, "ACCESS TOKEN")
    headers = {'Authorization': f'Zoho-oauthtoken {access_token}'}
    test_url = 'https://www.zohoapis.in/crm/v2/Leads'
    test_response = requests.get(test_url, headers=headers)
    
    if test_response.status_code == 401:  # Token expired
        logging.debug("Access token expired, refreshing token...")
        access_token = refresh_token(request)
        headers = {'Authorization': f'Zoho-oauthtoken {access_token}'}
        test_response = requests.get(test_url, headers=headers)
        if test_response.status_code == 401:
            logging.error('Token refresh failed')
            raise Exception('Token refresh failed')
    
    return access_token

def create_lead(request):
    if request.method == 'POST':
        try:
            access_token = get_access_token(request)
            lead_data = {
                'data': [
                    {
                        'Salutation': request.POST['salutation'],
                        'First_Name': request.POST['first_name'],
                        'Last_Name': request.POST['last_name'],
                        'Email': request.POST['email'],
                        'Phone': request.POST['phone'],
                        'Company': request.POST['company'],
                        'Lead_Source': request.POST['lead_source']
                    }
                ]
            }
            headers = {
                'Authorization': f'Zoho-oauthtoken {access_token}',
                'Content-Type': 'application/json'
            }
            response = requests.post('https://www.zohoapis.in/crm/v2/Leads', json=lead_data, headers=headers)
            response.raise_for_status()
            return JsonResponse({'message': 'Lead created successfully'})
        except requests.exceptions.RequestException as e:
            error_message = f"Error creating lead: {str(e)}"
            logging.error(error_message)
            return JsonResponse({'error': 'Error creating lead', 'details': str(e)}, status=response.status_code)
    return JsonResponse({'error': 'Invalid request method'}, status=400)

def leads(request):
    try:
        access_token = get_access_token(request)
        headers = {'Authorization': f'Zoho-oauthtoken {access_token}'}
        response = requests.get('https://www.zohoapis.in/crm/v2/Leads', headers=headers)
        response.raise_for_status()
        leads = response.json().get('data', [])
        return JsonResponse({'leads': leads})
    except Exception as e:
        logging.error(str(e))
        return JsonResponse({'error': str(e)}, status=500)
    
def delete_lead(request, lead_id):
    if request.method == 'DELETE':
        try:
            access_token = get_access_token(request)
            headers = {
                'Authorization': f'Zoho-oauthtoken {access_token}',
                'Content-Type': 'application/json'
            }
            response = requests.delete(f'https://www.zohoapis.in/crm/v2/Leads/{lead_id}', headers=headers)
            response.raise_for_status()
            return JsonResponse({'message': 'Lead deleted successfully'})
        except requests.exceptions.RequestException as e:
            error_message = f"Error deleting lead: {str(e)}"
            logging.error(error_message)
            return JsonResponse({'error': 'Error deleting lead', 'details': str(e)}, status=response.status_code)
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def index(request):
    return render(request, 'index.html')
