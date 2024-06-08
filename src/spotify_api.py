import requests
import os
from time import time
import random
from urllib.parse import urlparse, parse_qs
import string, json
import hashlib
import base64
import webbrowser


client_id = "0e1c7f14de25416f82fe507ed79d327e"
client_secret = "57230ccc3bd04fdca98841c738aadebe"
redirect_uri = "http://localhost:3000/callback"

def check_response(response):
    if response.status_code < 300:
        return True
    else:
        print(f"Request failed with status code {response.status_code}.")
        print(f"{response.content}.")
        return False

def check_token_time(token_expiration_time):
    '''
    Returns False if the token needs to be refreshed in a minute or less
    returns True if the token is still valid
    '''
    return ( token_expiration_time - time() ) > ( 1000 * 60 )

def generate_random_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def sha256(plain):
    return hashlib.sha256(plain.encode()).digest()

def base64encode(input):
    return base64.urlsafe_b64encode(input.encode()).decode().rstrip("=")

def authorize():
    '''
    PKCE Flow

    '''
    scope = 'user-read-private user-read-email'
    authUrl = "https://accounts.spotify.com/authorize"

    code_verifier = generate_random_string(64)
    hashed = sha256(code_verifier)
    code_challenge = base64encode(hashed)

    params =  {
        'response_type': 'code',
        'client_id': client_id,
        'scope': scope,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
        'redirect_uri': redirect_uri,
    }

    response = requests.get(authUrl, params=params)

    # Open the authorization URL in the default web browser
    webbrowser.open(response.url)
    parsed_url = urlparse(url)
    # Get the query parameters
    urlParams = parse_qs(parsed_url.query)

    # Get the 'code' parameter
    code = urlParams.get('code', [None])[0]


def get_token(client_id, client_secret):
    '''
    start a session: connect to app to get access_token
    '''
    url = "https://accounts.spotify.com/api/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "client_id": f"{client_id}",
        "client_secret": f"{client_secret}",
    }
    response = requests.post(url, headers=headers, data=data)
    if check_response(response):
        data = response.json()
        token_expiration_time = time() + 1000*int(data["expires_in"])
        with open("data/token.txt","w") as fh:
            fh.write(data["access_token"])
        return data["access_token"], token_expiration_time

def get_refresh_token(refresh_token, client_id):
    # refresh token that has been previously stored
    url = "https://accounts.spotify.com/api/token"

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': client_id  # replace with your client id
    }
    response = requests.post(url, headers=headers, data=data)
    if check_response(response):
        response_json = response.json()
        access_token = response_json['access_token']
        refresh_token = response_json['refresh_token']
        return access_token, refresh_token

def add_to_queue(token, song_uri, device_id=None):
    url = f"https://api.spotify.com/v1/me/player/queue?uri={song_uri}"
    if device_id:
        url += f"?device_id={device_id}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    response = requests.post(url, headers=headers)
    return check_response(response)

def find_track(token, artist=None, name=None):
    '''
    Takes in artist and song name parameters, one of which is requried
    returns a list of tuples containing the (name, popularity, uri) of the first 10 results
    '''
    # build and send the request
    q_string = ""
    if artist:
        q_string += artist
    if name:
        for word in name.split():
            q_string += "%20"+word
    if not q_string: return None
    url = f"https://api.spotify.com/v1/search?q={q_string}&type=track&limit=10"
    headers = {
        f"Authorization": f"Bearer {token}",
    }
    response = requests.get(url, headers=headers)
    # check the request
    if not check_response(response):
        pass
    # parse
    data = response.content
    dic = json.loads(data.decode('utf-8'))
    # return the top tracks sorted by popularity
    tracks = []
    for track in dic['tracks']['items']:
        tracks.append((track['name'], track['popularity'], track['uri'].split(':')[-1]))
    tracks.sort(key=lambda x: x[1], reverse=True)
    return tracks

def get_track(token, track_id):
    '''
    takes in a track_id
    returns the information for the song
    should not need to be used for this app
    '''
    # build and send the request
    url = f"https://api.spotify.com/v1/tracks/{track_id}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    response = requests.get(url, headers=headers)
    if check_response(response):
        data = response.content
        dic = json.loads(data.decode('utf-8'))
        return (dic['name'], dic['artists'], dic['album'])

def get_artist(token, artist_id):
    url = f"https://api.spotify.com/v1/artists/{artist_id}"
    headers = {
        "Authorization": f"Bearer {token}",
    }
    response = requests.get(url, headers=headers)
    if check_response(response):
        data = response.content
        dic = json.loads(data.decode('utf-8'))

if __name__ == '__main__':
    token, expiration_time = get_token(client_id, client_secret)
    # check_token_time(expiration_time)
    top_tracks = find_track(token, name="thunder")
    ret = add_to_queue(token, top_tracks[0][2])
    print(ret)