# -*- coding: utf-8 -*-
"""
Provide a simple wrapper around Deezer API (with streaming).
"""

import hashlib
from math import ceil
import pickle
from random import randint
from time import time
from Cryptodome.Hash import MD5
from Cryptodome.Cipher import Blowfish, AES
import requests
import xbmcvfs

from lib import Settings
from lib.exceptions import ApiExceptionFinder, LoadedCredentialsException, EmptyCredentialsException
from lib.helpers.logger import Logger


class Api(object):
    """
    Api class holds user login and password.
    It is responsible for obtaining access_token automatically when a request is made
    """

    _API_BASE_URL = "http://api.deezer.com/2.0/{service}/{id}/{method}"
    _API_BASE_STREAMING_URL = "https://media.deezer.com/v1/get_url"
    _API_AUTH_URL = "https://connect.deezer.com/oauth/user_auth.php"
    _API_BASE_GW_URL = 'https://www.deezer.com/ajax/gw-light.php'
    _CLIENT_ID = "447462"
    _CLIENT_SECRET = "a83bf7f38ad2f137e444727cfc3775cf"
    __CACHE_FILE = xbmcvfs.translatePath('special://temp/deezer-api.pickle')

    __INSTANCE = None

    @classmethod
    def instance(cls):
        """
        Gets the running instance of the API.
        If no instance is running, tries to get it from file.
        Else creates a new instance and tries to get a token from Deezer API.

        :return:
        """
        Logger.debug("Getting Api instance ...")

        if cls.__INSTANCE is None:
            try:
                Logger.debug("Trying to get Api instance from file ...")
                cls.__INSTANCE = cls.load()
            except IOError:
                Logger.debug("Api instance not saved, trying to get token ...")

                cls.__INSTANCE = cls(
                    Settings.get('email'),
                    Settings.get('password')
                )
            except LoadedCredentialsException:
                Logger.warn("Loaded bad API credentials, trying from settings values ...")
                cls.clean_cache()

                cls.__INSTANCE = cls(
                    Settings.get('email'),
                    Settings.get('password')
                )

        return cls.__INSTANCE

    @classmethod
    def clean_cache(cls) -> None:
        """Cleans the API cache"""
        Logger.debug("Cleaning API cache ...")
        xbmcvfs.delete(Api.__CACHE_FILE)
        cls.__INSTANCE = None

    def __init__(self, email: str, password: str):
        """
        Instantiate a Connection object from email and password.

        :param str email: The user's email
        :param str password: The user's password
        :raise EmptyCredentialsException: If the credentials are empty
        """
        Logger.debug("Creating new API connection ...")
        self._email = email
        self._password = ""
        self.set_password(password)
        self._access_token = None

        if self.empty_credentials():
            raise EmptyCredentialsException("email and password are required!")

        self.s = requests.Session()
        self.s.headers.update({
            'accept': '*/*',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'content-type': 'text/plain;charset=UTF-8',
            'origin': 'https://www.deezer.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'same-origin',
            'sec-fetch-dest': 'empty',
            'referer': 'https://www.deezer.com/',
            'accept-language': 'en-US,en;q=0.9',
        })
        self.s.get('https://www.deezer.com')

        self._obtain_access_token()

        self._obtain_api_token()

    def set_password(self, password: str) -> None:
        """
        Save md5 of user password.

        :param str password: The user's password to save
        """
        md5 = hashlib.md5()
        md5.update(password.encode("utf-8"))
        self._password = md5.hexdigest()

    def save(self) -> None:
        """
        Save the connection to a file in kodi special temp folder.
        """
        Logger.debug("Saving Api in '{}'".format(Api.__CACHE_FILE))

        with open(Api.__CACHE_FILE, 'wb') as file:
            pickle.dump(self, file, pickle.HIGHEST_PROTOCOL)

    @staticmethod
    def load(cache_file: str = __CACHE_FILE):
        """
        Loads a connection from a file.

        :return: an Api object
        """
        Logger.debug("Getting Api from file {}".format(cache_file))

        with open(cache_file, 'rb') as file:
            cls = pickle.load(file)

        if cls.empty_credentials(check_token=True):
            raise LoadedCredentialsException("Loaded empty email or password")

        return cls

    def empty_credentials(self, check_token: bool = False) -> bool:
        """
        Checks if credentials are empty.

        :param check_token: Tells wether or not to check the access token
        :return: True if any credential is empty, False if there are all filled
        """
        empty_creds = self._email == "" or self._password == ""
        empty_tok = False

        if check_token:
            empty_tok = self._access_token is None

        return empty_creds or empty_tok

    def _obtain_access_token(self) -> None:
        """
        Obtain access token by pretending to be a smart tv.
        """
        Logger.debug("Connection: Getting access token from API ...")
        hashed_params = hashlib.md5(f'{self._CLIENT_ID}{self._email}{self._password}{self._CLIENT_SECRET}'.encode('utf-8')).hexdigest()
        url = f'{self._API_AUTH_URL}?app_id={self._CLIENT_ID}&login={self._email}&password={self._password}&hash={hashed_params}'
        response = self.s.get(url).json()
        Api.check_error(response)
        self._access_token = response['access_token']


    def _obtain_api_token(self) -> None:
        """
        Obtain api token from gw_api.
        """
        Logger.debug("Connection: Getting api token ...")
        self.call_gw_api('deezer.getUserData')
        # TODO : allow login with ARL
        #arl = self.call_gw_api('user.getArl')
        #self.s.cookies.set('arl', self._arl, domain='.deezer.com')


    def call_gw_api(self, method, payload={}):
        api_token = '' if method in ('deezer.getUserData', 'user.getArl') else self.api_token
        params = {
            'method': method,
            'input': 3,
            'api_version': 1.0,
            'api_token': api_token,
            'cid': randint(0, 1_000_000_000),
        }
        resp = self.s.post(self._API_BASE_GW_URL, params=params, json=payload).json()
        if resp['error']!=[]:
            self.s.cookies.clear()
            Logger.debug(f"Error: {resp['error']}")
        else:
            resp = resp['results']
            if method == 'deezer.getUserData':
                self.api_token = resp['checkForm']
                self.country = resp['COUNTRY']
                self.license_token = resp['USER']['OPTIONS']['license_token']
                self.renew_timestamp = ceil(time())
                self.language = resp['USER']['SETTING']['global']['language']
                self.available_formats = ['MP3_128']
                format_dict = {'web_hq': 'MP3_320', 'web_lossless': 'FLAC'}
                for k, v in format_dict.items():
                    if resp['USER']['OPTIONS'][k]:
                        self.available_formats.append(v)
            print(self.available_formats)
        return resp


    def request(
            self,
            service: str,
            identifiant: str = '',
            method: str = '',
            parameters: str = None
    ):
        """
        Make request to the API and return response as a dict.\n
        Parameters names are the same as described in
        the Deezer API documentation (https://developers.deezer.com/api).

        :param str service:     The service to request
        :param str identifiant: Item's ID in the service
        :param str method:      Service method
        :param dict parameters: Additional parameters at the end
        :return:                JSON response as dict
        """
        Logger.debug(
            "Requesting {} ...".format('/'.join([str(service), str(identifiant), str(method)]))
        )

        if parameters is None:
            parameters = {}

        url = self._API_BASE_URL.format(service=service, id=identifiant, method=method)
        response = self.s.get(url, params=_merge_two_dicts(
            {'output': 'json', 'access_token': self._access_token},
            parameters
        )).json()

        # if there is a next url, call it
        if 'next' in response:
            response['data'] += Api.request_url(response['next'])['data']

        Api.check_error(response)

        return response

    @staticmethod
    def request_url(url: str):
        """
        Send a GET request to `url`.

        :param str url: Url to query
        :return: JSON response as dict
        """
        Logger.debug("Making custom request ...")

        response = requests.get(url).json()

        # if there is a next url, call it and append data
        if 'next' in response:
            response['data'] += Api.request_url(response['next'])['data']

        Api.check_error(response)

        return response


    def get_track_url(self, id, track_token, track_token_expiry, format):
        # renews license token
        if time() - self.renew_timestamp >= 3600:
            self.call_gw_api('deezer.getUserData')
        # renews track token
        if time() - track_token_expiry >= 0:
            track_token = self.call_gw_api('song.getData', {'sng_id': id, 'array_default': ['TRACK_TOKEN']})['TRACK_TOKEN']
        json = {
            'license_token': self.license_token,
            'media': [
                {
                    'type': 'FULL',
                    'formats': [{'cipher': 'BF_CBC_STRIPE', 'format': format}]
                }
            ],
            'track_tokens': [track_token]
        }
        resp = self.s.post(self._API_BASE_STREAMING_URL, json=json).json()
        return resp['data'][0]['media'][0]['sources'][0]['url']
    

    def get_legacy_track_url(self, md5_origin, format, id, media_version):
        format_num = {
            'MP3_MISC': '0',
            'MP3_128': '1',
            'MP4_RA1': '13',
            'MP4_RA2': '14',
            'MP4_RA3': '15',
            'MHM1_RA1': '16',
            'MHM1_RA2': '17',
            'MHM1_RA3': '18'
        }[format]
        # mashing a bunch of metadata and hashing it with MD5
        info = b"\xa4".join([i.encode() for i in [
            md5_origin, format_num, str(id), str(media_version)
        ]])
        hash = MD5.new(info).hexdigest()
        # hash + metadata
        hash_metadata = hash.encode() + b"\xa4" + info + b"\xa4"
        # padding
        while len(hash_metadata) % 16 > 0:
            hash_metadata += b"\0"
        # AES encryption
        track_url_key = "jo6aey6haid2Teih" 
        legacy_url_cipher = AES.new(track_url_key.encode('ascii'), AES.MODE_ECB)
        result = legacy_url_cipher.encrypt(hash_metadata).hex()
        # getting url
        return f"https://cdns-proxy-{md5_origin[0]}.dzcdn.net/mobile/1/{result}"
    

    def dl_track(self, id, url, path):
        md5_id = MD5.new(str(id).encode()).hexdigest().encode('ascii')
        bf_secret = "g4el58wc0zvf9na1".encode('ascii')
        bf_key = bytes([md5_id[i] ^ md5_id[i + 16] ^ bf_secret[i] for i in range(16)])
        req = requests.get(url, stream=True)
        req.raise_for_status()
        with open(path, "wb") as file:
            for i, chunk in enumerate(req.iter_content(2048)):
                # every 3rd chunk is encrypted
                if i % 3 == 0 and len(chunk) == 2048:
                    # yes, the cipher has to be reset on every chunk.
                    # those deezer devs were prob smoking crack when they made this DRM
                    cipher = Blowfish.new(bf_key, Blowfish.MODE_CBC, b"\x00\x01\x02\x03\x04\x05\x06\x07")
                    chunk = cipher.decrypt(chunk)
                file.write(chunk)


    def request_streaming(self, identifiant: str = '', st_type: str = 'track'):
        """
        Make a request to get the streaming url of `type` with `id`.

        :param str identifiant: ID of the requested item
        :param str st_type: Type of the requested item
        :return: Dict if type is radio or artist, str otherwise
        """
        Logger.info(
            "Connection: Requesting streaming for {} with id {} ...".format(st_type, identifiant)
        )

        if time() - self.renew_timestamp >= 3600:
            self.call_gw_api('deezer.getUserData')
        t_data = self.call_gw_api('deezer.pageTrack', {'sng_id': identifiant})['DATA']
        print(t_data)
        id = t_data['SNG_ID']
        track_token = t_data['TRACK_TOKEN']
        track_token_expiry = t_data['TRACK_TOKEN_EXPIRE']
        format = self.available_formats[-1]
        md5_origin = t_data['MD5_ORIGIN']
        media_version = t_data['MEDIA_VERSION']
        if format in ('MP3_320', 'FLAC'):
            url = self.get_track_url(id, track_token, track_token_expiry, format)
        else:
            url = self.get_legacy_track_url(md5_origin, format, id, media_version)

        return url


    @staticmethod
    def check_error(response):
        """
        Checks for errors in every response.
        If errors are found, throws the corresponding exception.

        :param response: The json response to check
        :return: The verified json response
        """
        if 'error' in response:
            ApiExceptionFinder.from_error(response['error'])

        return response


def _merge_two_dicts(lhs: dict, rhs: dict) -> dict:
    """
    Given two dicts, merge them into a new dict as a shallow copy.

    :param dict lhs: First dict
    :param dict rhs: Second dict
    :return: Merged dict
    """
    res = lhs.copy()
    res.update(rhs)
    return res
