
import json
import requests
import base64

from walkoff_app_sdk.app_base import AppBase

class OracleIAM(AppBase):
    __version__ = "1.0.0"
    app_name = "oracle-iam"  

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)


    def authenticate(self, username, password, url):
        s = requests.Session()
        auth_url = f"{url}/iam/governance/token/api/v1/tokens"
        client_id_and_secret = f'{username}:{password}'

        # Standard Base64 Encoding
        encodedBytes = base64.b64encode(client_id_and_secret.encode('utf-8'))
        encodedStr = str(encodedBytes, 'utf-8')

        auth_headers = {
            'Authorization': f'Basic {encodedStr}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-REQUESTED-BY': 'Shuffle'
        }

        auth_data = {
            'grant_type': 'client_credentials',
            'scope': 'urn:opc:idm:__myscopes__',
        }

        print(f"Making request to: {auth_url}")
        res = s.post(auth_url, data=auth_data, headers=auth_headers, verify=False)

        # Auth failed, raise exception with the response
        if res.status_code != 201:
            raise ConnectionError(res.text)

        access_token = res.json().get("accessToken")
        s.headers = {
            "Authorization": f"Bearer {access_token}",
            "X-REQUESTED-BY": "Shuffle",
            "Content-Type": "application/scim+json",
            "Accept": "application/scim+json"
            }
        return s

    def get_user_id(self, url, session, userid=""):
        query_params = {
                'schemas':['urn:ietf:params:scim:api:messages:2.0:SearchRequest'],  
                'attributes': [ 'id', 'userName','active','displayName'],
                'filter': f'userName eq {userid}',
                'startIndex':1,
                'count':2,
                'sortBy': 'userName',
                'sortOrder': 'ascending'
        }
        api_url = f"{url}/iam/governance/scim/v1/Users/.search"
        ret = session.post(api_url, json=query_params, verify=False)
        ret_json = json.loads(ret.text)
        if ret_json.get("totalResults") == 1:
            return ret_json["Resources"][0]["id"]
        else:
            return None

    def get_user(self, username, password,  url, userid=""):
        session = self.authenticate(username, password, url)
        systemUserID = self.get_user_id(url, session, userid)
        if systemUserID is not None:
            api_url = f"{url}/iam/governance/scim/v1/Users/{systemUserID}"
            ret = session.get(api_url, verify=False)
            return ret.text
        else:
            return "No user found."
    

    

# Run the actual thing after we've checked params
def run(request):
    action = request.get_json()
    authorization_key = action.get("authorization")
    current_execution_id = action.get("execution_id")

    if action and "name" in action and "app_name" in action:
        OracleIAM.run(action)
        return f'Attempting to execute function {action["name"]} in app {action["app_name"]}'
    else:
        return f"Invalid action"

if __name__ == "__main__":
    OracleIAM.run()
